package container

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

type containerServer struct {
	socket *socket
	containerConfig
}

// Init is called for container init process
// it will check if pid == 1, otherwise it is noop
// Init will do infinite loop on socket commands,
// and exits when at socket close, use it in init function
func Init() (err error) {
	// noop if self is not container init process
	// Notice: docker init is also 1, additional check for args[1] == init
	if os.Getpid() != 1 || len(os.Args) < 2 || os.Args[1] != initArg {
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

	// new_container environment shared the socket at fd 3 (marked close_exec)
	const defaultFd = 3
	soc, err := unixsocket.NewSocket(defaultFd)
	if err != nil {
		return fmt.Errorf("container_init: failed to new socket %v", err)
	}

	// serve forever
	cs := &containerServer{socket: newSocket(soc)}
	return cs.serve()
}

func (c *containerServer) serve() error {
	for {
		cmd, msg, err := c.recvCmd()
		if err != nil {
			return fmt.Errorf("serve: recvCmd %v", err)
		}
		if err := c.handleCmd(cmd, msg); err != nil {
			return fmt.Errorf("serve: failed to execute cmd %v", err)
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

func initContainer(c containerConfig) error {
	if err := initFileSystem(c); err != nil {
		return err
	}
	if err := syscall.Setdomainname([]byte(c.DomainName)); err != nil {
		return err
	}
	if err := syscall.Sethostname([]byte(c.HostName)); err != nil {
		return err
	}
	return os.Chdir(c.WorkDir)
}

func initFileSystem(c containerConfig) error {
	// mount tmpfs as root
	const tmpfs = "tmpfs"
	if err := syscall.Mount(tmpfs, c.ContainerRoot, tmpfs, 0, ""); err != nil {
		return fmt.Errorf("init_fs: mount / %v", err)
	}
	// change dir to container root
	if err := syscall.Chdir(c.ContainerRoot); err != nil {
		return fmt.Errorf("init_fs: chdir %v", err)
	}
	// performing mounts
	for _, m := range c.Mounts {
		if err := m.Mount(); err != nil {
			return fmt.Errorf("init_fs: mount %v %v", m, err)
		}
	}
	// pivot root
	const oldRoot = "old_root"
	if err := os.Mkdir(oldRoot, 0755); err != nil {
		return fmt.Errorf("init_fs: mkdir(old_root) %v", err)
	}
	if err := syscall.PivotRoot(c.ContainerRoot, oldRoot); err != nil {
		return fmt.Errorf("init_fs: pivot_root(%s, %s) %v", c.ContainerRoot, oldRoot, err)
	}
	if err := syscall.Unmount(oldRoot, syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("init_fs: unmount(old_root) %v", err)
	}
	if err := os.Remove(oldRoot); err != nil {
		return fmt.Errorf("init_fs: unlink(old_root) %v", err)
	}
	// readonly root
	const remountFlag = syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY | syscall.MS_NOATIME | syscall.MS_NOSUID
	if err := syscall.Mount(tmpfs, "/", tmpfs, remountFlag, ""); err != nil {
		return fmt.Errorf("init_fs: readonly remount / %v", err)
	}
	return nil
}
