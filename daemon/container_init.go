package daemon

import (
	"fmt"
	"io"
	"os"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

type containerServer struct {
	socket *unixsocket.Socket
	containerConfig
}

type containerConfig struct {
	Cred bool
}

// Init is called for container init process
// it will check if pid == 1, otherwise it is noop
// Init will do infinite loop on socket commands,
// and exits when at socket close, use it in init function
func Init() (err error) {
	// noop if self is not container init process
	// Notice: docker init is also 1, additional check for args[1] == init
	if os.Getpid() != 1 || len(os.Args) != 2 || os.Args[1] != initArg {
		return nil
	}

	// exit process (with whole container) upon exit this function
	// possible reason:
	// 1. socket broken (parent exit)
	// 2. panic
	// 3. undefined cmd (possible race condition)
	defer func() {
		if err2 := recover(); err2 != nil {
			fmt.Fprintf(os.Stderr, "container_panic: %v\n", err)
			os.Exit(1)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "container_exit: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "container_exit\n")
		os.Exit(0)
	}()

	// new_master shared the socket at fd 3 (marked close_exec)
	const defaultFd = 3
	soc, err := unixsocket.NewSocket(defaultFd)
	if err != nil {
		return fmt.Errorf("container_init: failed to new socket(%v)", err)
	}

	// serve forever
	cs := &containerServer{socket: soc}
	return cs.serve()
}

func (c *containerServer) serve() error {
	for {
		cmd, msg, err := c.recvCmd()
		if err != nil {
			return fmt.Errorf("serve: %v", err)
		}
		if err := c.handleCmd(cmd, msg); err != nil {
			return fmt.Errorf("serve: failed to execute cmd %v", err)
		}
	}
}

func (c *containerServer) handleCmd(cmd *Cmd, msg *unixsocket.Msg) error {
	switch cmd.Cmd {
	case cmdPing:
		return c.handlePing()

	case cmdConf:
		return c.handleConf(cmd)

	case cmdCopyIn:
		return c.handleCopyIn(cmd, msg)

	case cmdOpen:
		return c.handleOpen(cmd)

	case cmdDelete:
		return c.handleDelete(cmd)

	case cmdReset:
		return c.handleReset()

	case cmdExecve:
		return c.handleExecve(cmd, msg)
	}
	return fmt.Errorf("unknown command: %v", cmd.Cmd)
}

func (c *containerServer) handlePing() error {
	return c.sendReply(&Reply{}, nil)
}

func (c *containerServer) handleConf(cmd *Cmd) error {
	if cmd.Conf != nil {
		c.containerConfig = *cmd.Conf
	}
	return c.sendReply(&Reply{}, nil)
}

func (c *containerServer) handleCopyIn(cmd *Cmd, msg *unixsocket.Msg) error {
	if len(msg.Fds) != 1 {
		closeFds(msg.Fds)
		return c.sendErrorReply("copyin: unexpected number of fds(%d)", len(msg.Fds))
	}
	inf := os.NewFile(uintptr(msg.Fds[0]), cmd.Path)
	if inf == nil {
		return c.sendErrorReply("copyin: newfile failed %v", msg.Fds[0])
	}
	defer inf.Close()

	// have 0777 permission to be able copy in executables
	outf, err := os.OpenFile(cmd.Path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0777)
	if err != nil {
		return c.sendErrorReply("copyin: open write file %v", err)
	}
	defer outf.Close()

	if _, err = io.Copy(outf, inf); err != nil {
		return c.sendErrorReply("copyin: io.copy %v", err)
	}
	return c.sendReply(&Reply{}, nil)
}

func (c *containerServer) handleOpen(cmd *Cmd) error {
	outf, err := os.Open(cmd.Path)
	if err != nil {
		return c.sendErrorReply("open: %v", err)
	}
	defer outf.Close()

	return c.sendReply(&Reply{}, &unixsocket.Msg{
		Fds: []int{int(outf.Fd())},
	})
}

func (c *containerServer) handleDelete(cmd *Cmd) error {
	if err := os.Remove(cmd.Path); err != nil {
		return c.sendErrorReply("delete: %v", err)
	}
	return c.sendReply(&Reply{}, nil)
}

func (c *containerServer) handleReset() error {
	if err := removeContents("/tmp"); err != nil {
		return c.sendErrorReply("reset: /tmp %v", err)
	}
	if err := removeContents("/w"); err != nil {
		return c.sendErrorReply("reset: /w %v", err)
	}
	return c.sendReply(&Reply{}, nil)
}

func (c *containerServer) recvCmd() (*Cmd, *unixsocket.Msg, error) {
	cmd := new(Cmd)
	msg, err := (*socket)(c.socket).RecvMsg(cmd)
	if err != nil {
		return nil, nil, err
	}
	return cmd, msg, nil
}

func (c *containerServer) sendReply(reply *Reply, msg *unixsocket.Msg) error {
	return (*socket)(c.socket).SendMsg(reply, msg)
}

// sendErrorReply sends error reply
func (c *containerServer) sendErrorReply(ft string, v ...interface{}) error {
	return c.sendReply(&Reply{Error: fmt.Sprintf(ft, v...)}, nil)
}
