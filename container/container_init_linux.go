package container

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

type containerServer struct {
	socket *socket
	containerConfig

	done     chan struct{}
	err      error
	doneOnce sync.Once

	recvCh chan recvCmd
	sendCh chan sendReply

	waitPid       chan int
	waitPidResult chan waitPidResult

	waitAll     chan struct{}
	waitAllDone chan struct{}
}

type recvCmd struct {
	Cmd cmd
	Msg unixsocket.Msg
}

type sendReply struct {
	Reply       reply
	Msg         unixsocket.Msg
	FileToClose []*os.File
}

type waitPidResult struct {
	WaitStatus syscall.WaitStatus
	Rusage     syscall.Rusage
	Err        error
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

	// ensure there's no fd leak to child process (e.g. VSCode leaks ptmx fd)
	if err := closeOnExecAllFds(); err != nil {
		return fmt.Errorf("container_init: failed to close_on_exec all fd %v", err)
	}

	// new_container environment shared the socket at fd 3 (marked close_exec)
	const defaultFd = 3
	soc, err := unixsocket.NewSocket(defaultFd)
	if err != nil {
		return fmt.Errorf("container_init: failed to new socket %v", err)
	}

	// serve forever
	cs := &containerServer{
		socket:        newSocket(soc),
		done:          make(chan struct{}),
		sendCh:        make(chan sendReply, 1),
		recvCh:        make(chan recvCmd, 1),
		waitPid:       make(chan int),
		waitAll:       make(chan struct{}),
		waitPidResult: make(chan waitPidResult, 1),
		waitAllDone:   make(chan struct{}, 1),
	}
	go cs.sendLoop()
	go cs.recvLoop()
	go cs.waitLoop()

	return cs.serve()
}

func (c *containerServer) sendLoop() {
	for {
		select {
		case <-c.done:
			return

		case rep, ok := <-c.sendCh:
			if !ok {
				return
			}
			err := c.socket.SendMsg(rep.Reply, rep.Msg)
			for _, f := range rep.FileToClose {
				f.Close()
			}
			if err != nil {
				c.socketError(err)
				return
			}
		}
	}
}

func (c *containerServer) recvLoop() {
	for {
		var cmd cmd
		msg, err := c.socket.RecvMsg(&cmd)
		if err != nil {
			c.socketError(err)
			return
		}
		c.recvCh <- recvCmd{
			Cmd: cmd,
			Msg: msg,
		}
	}
}

func (c *containerServer) socketError(err error) {
	c.doneOnce.Do(func() {
		c.err = err
		close(c.done)
	})
}

func (c *containerServer) waitLoop() {
	for {
		select {
		case pid := <-c.waitPid:
			var waitStatus syscall.WaitStatus
			var rusage syscall.Rusage

			_, err := syscall.Wait4(pid, &waitStatus, 0, &rusage)
			for err == syscall.EINTR {
				_, err = syscall.Wait4(pid, &waitStatus, 0, &rusage)
			}
			if err != nil {
				c.waitPidResult <- waitPidResult{
					Err: err,
				}
				continue
			}
			c.waitPidResult <- waitPidResult{
				WaitStatus: waitStatus,
				Rusage:     rusage,
			}

		case <-c.waitAll:
			for {
				if _, err := syscall.Wait4(-1, nil, syscall.WNOHANG, nil); err != nil && err != syscall.EINTR {
					break
				}
			}
			c.waitAllDone <- struct{}{}
		}
	}
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

func (c *containerServer) handleCmd(cmd cmd, msg unixsocket.Msg) error {
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
	// create symlinks
	for _, l := range c.SymbolicLinks {
		// ensure dir exists
		dir := filepath.Dir(l.LinkPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("init_fs: mkdir_all(%s) %v", dir, err)
		}
		if err := os.Symlink(l.Target, l.LinkPath); err != nil {
			return fmt.Errorf("init_fs: symlink %v", err)
		}
	}
	// mask paths
	for _, p := range c.MaskPaths {
		if err := maskPath(p); err != nil {
			return fmt.Errorf("init_fs: mask path %v", err)
		}
	}
	// readonly root
	const remountFlag = syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY | syscall.MS_NOATIME | syscall.MS_NOSUID
	if err := syscall.Mount(tmpfs, "/", tmpfs, remountFlag, ""); err != nil {
		return fmt.Errorf("init_fs: readonly remount / %v", err)
	}
	return nil
}

func (c *containerServer) recvCmd() (cmd, unixsocket.Msg, error) {
	select {
	case <-c.done:
		return cmd{}, unixsocket.Msg{}, c.err

	case recv := <-c.recvCh:
		return recv.Cmd, recv.Msg, nil
	}
}

func (c *containerServer) sendReplyFiles(rep reply, msg unixsocket.Msg, fileToClose []*os.File) error {
	select {
	case <-c.done:
		return c.err

	case c.sendCh <- sendReply{Reply: rep, Msg: msg}:
		return nil
	}
}

func (c *containerServer) sendReply(rep reply, msg unixsocket.Msg) error {
	return c.sendReplyFiles(rep, msg, nil)
}

// sendErrorReply sends error reply
func (c *containerServer) sendErrorReply(ft string, v ...interface{}) error {
	errRep := &errorReply{
		Msg: fmt.Sprintf(ft, v...),
	}
	// store errno
	if len(v) == 1 {
		if errno, ok := v[0].(syscall.Errno); ok {
			errRep.Errno = &errno
		}
	}
	return c.sendReply(reply{Error: errRep}, unixsocket.Msg{})
}

func closeOnExecAllFds() error {
	// get all fd from /proc/self/fd
	const fdPath = "/proc/self/fd"
	fds, err := os.ReadDir(fdPath)
	if err != nil {
		return err
	}
	for _, f := range fds {
		fd, err := strconv.Atoi(f.Name())
		if err != nil {
			return err
		}
		syscall.CloseOnExec(fd)
	}
	return nil
}

func maskPath(path string) error {
	// bind mount /dev/null if it is file
	if err := syscall.Mount("/dev/null", path, "", syscall.MS_BIND, ""); err != nil && !errors.Is(err, os.ErrNotExist) {
		if errors.Is(err, syscall.ENOTDIR) {
			// otherwise, mount tmpfs to mask it
			return syscall.Mount("tmpfs", path, "tmpfs", syscall.MS_RDONLY, "")
		}
		return err
	}
	return nil
}
