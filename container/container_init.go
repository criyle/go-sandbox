package container

import (
	"fmt"
	"os"
	"runtime"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

type containerServer struct {
	socket *unixsocket.Socket
	containerConfig
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
		if err := recover(); err != nil {
			fmt.Fprintf(os.Stderr, "container_exit: panic: %v\n", err)
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
		return fmt.Errorf("container_init: failed to new socket %w", err)
	}

	// serve forever
	cs := &containerServer{socket: soc}
	return cs.serve()
}

func (c *containerServer) serve() error {
	for {
		cmd, msg, err := c.recvCmd()
		if err != nil {
			return fmt.Errorf("serve: recvCmd %w", err)
		}
		if err := c.handleCmd(cmd, msg); err != nil {
			return fmt.Errorf("serve: failed to execute cmd %w", err)
		}
	}
}

func (c *containerServer) handleCmd(cmd *cmd, msg *unixsocket.Msg) error {
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
	return fmt.Errorf("unknown command: %s", cmd.Cmd)
}
