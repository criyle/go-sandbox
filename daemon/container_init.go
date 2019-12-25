package daemon

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

type containerServer struct {
	socket *unixsocket.Socket
	containerConfig
}

// ContainerConfig set the container config
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

	// limit container resource usage
	runtime.GOMAXPROCS(containerMaxProc)

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
		return c.handleConf(cmd.ConfCmd)

	case cmdOpen:
		return c.handleOpen(cmd.OpenCmd)

	case cmdDelete:
		return c.handleDelete(cmd.DeleteCmd)

	case cmdReset:
		return c.handleReset()

	case cmdExecve:
		return c.handleExecve(cmd.ExecCmd, msg)
	}
	return fmt.Errorf("unknown command: %v", cmd.Cmd)
}

func (c *containerServer) handlePing() error {
	return c.sendReply(&Reply{}, nil)
}

func (c *containerServer) handleConf(conf *ConfCmd) error {
	if conf != nil {
		c.containerConfig = conf.Conf
	}
	return c.sendReply(&Reply{}, nil)
}

func (c *containerServer) handleOpen(open []OpenCmd) error {
	if len(open) == 0 {
		return c.sendErrorReply("open: no open parameter received")
	}

	// open files
	fds := make([]int, 0, len(open))
	for _, o := range open {
		outFile, err := os.OpenFile(o.Path, o.Flag, o.Perm)
		if err != nil {
			return c.sendErrorReply("open: %v", err)
		}
		defer outFile.Close()
		fds = append(fds, int(outFile.Fd()))
	}

	return c.sendReply(&Reply{}, &unixsocket.Msg{Fds: fds})
}

func (c *containerServer) handleDelete(delete *DeleteCmd) error {
	if delete == nil {
		return c.sendErrorReply("delete: no parameter provided")
	}
	if err := os.Remove(delete.Path); err != nil {
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
	errorReply := &ErrorReply{
		Msg: fmt.Sprintf(ft, v...),
	}
	// store errno
	if len(v) == 1 {
		if errno, ok := v[0].(syscall.Errno); ok {
			errorReply.Errno = &errno
		}
	}
	return c.sendReply(&Reply{Error: errorReply}, nil)
}
