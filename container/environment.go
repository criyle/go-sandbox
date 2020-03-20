package container

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/pkg/mount"
	"github.com/criyle/go-sandbox/pkg/unixsocket"
	"github.com/criyle/go-sandbox/runner"
	"golang.org/x/sys/unix"
)

// PathEnv defines path environment variable for the container init process
const PathEnv = "PATH=/usr/local/bin:/usr/bin:/bin"

// Builder builds instance of container environment
type Builder struct {
	// Root is container root mount path, empty uses current work path
	Root string

	// Mounts defines container mount points, empty uses default mounts
	Mounts []mount.SyscallParams

	// Stderr defines whether to dup container stderr to stderr for debug
	Stderr bool

	// ExecFile defines executable that called Init, otherwise defer current
	// executable (/proc/self/exe)
	ExecFile *os.File

	// CredGenerator defines a credential generator used to create new container
	CredGenerator CredGenerator

	// Clone flags defines unshare clone flag to create container
	CloneFlags uintptr
}

// CredGenerator generates uid / gid credential used by container
// to isolate process and file system access
type CredGenerator interface {
	Get() syscall.Credential
}

// Environment holds single progrem containerized environment
type Environment interface {
	Ping() error
	Open([]OpenCmd) ([]*os.File, error)
	Delete(p string) error
	Reset() error
	Execve(context.Context, ExecveParam) <-chan runner.Result
	Destroy() error
}

// container manages single pre-forked container environment
type container struct {
	pid    int        // underlying container init pid
	socket *socket    // host - container communication
	mu     sync.Mutex // lock to avoid race condition
}

// Build creates new environment with underlying container
func (b *Builder) Build() (Environment, error) {
	var (
		err            error
		cred           syscall.Credential
		uidMap, gidMap []syscall.SysProcIDMap
	)

	// container mount points
	mounts := b.Mounts
	if len(mounts) == 0 {
		if mounts, err = mount.NewDefaultBuilder().
			WithTmpfs("w", "").   // work dir
			WithTmpfs("tmp", ""). // tmp
			Build(true); err != nil {
			return nil, fmt.Errorf("container: failed to build rootfs mount %v", err)
		}
	}

	// container root directory on the host
	root := b.Root
	if root == "" {
		if root, err = os.Getwd(); err != nil {
			return nil, fmt.Errorf("container: failed to get work directory %v", err)
		}
	}

	// prepare stdin / stdout / stderr
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("container: failed to open devNull %v", err)
	}
	defer devNull.Close()

	files := make([]uintptr, 0, 4)
	files = append(files, devNull.Fd(), devNull.Fd())
	if b.Stderr {
		files = append(files, os.Stderr.Fd())
	} else {
		files = append(files, devNull.Fd())
	}

	// prepare container exec file
	execFile, err := b.exec()
	if err != nil {
		return nil, fmt.Errorf("container: prepare exec %v", err)
	}
	defer execFile.Close()

	// prepare host <-> container unix socket
	ins, outs, err := newPassCredSocketPair()
	if err != nil {
		return nil, fmt.Errorf("container: failed to create socket: %v", err)
	}
	defer outs.Close()

	outf, err := outs.File()
	if err != nil {
		ins.Close()
		return nil, fmt.Errorf("container: failed to dup container socket fd %v", err)
	}
	defer outf.Close()

	files = append(files, uintptr(outf.Fd()))

	// prepare container running credential
	if b.CredGenerator != nil {
		cred = b.CredGenerator.Get()
		uidMap, gidMap = getIDMapping(&cred)
	}

	var cloneFlag uintptr
	if b.CloneFlags == 0 {
		cloneFlag = forkexec.UnshareFlags
	} else {
		cloneFlag = b.CloneFlags & forkexec.UnshareFlags
	}

	r := &forkexec.Runner{
		Args:        []string{os.Args[0], initArg},
		Env:         []string{PathEnv},
		ExecFile:    execFile.Fd(),
		Files:       files,
		WorkDir:     containerWD,
		CloneFlags:  cloneFlag,
		Mounts:      mounts,
		HostName:    containerName,
		DomainName:  containerName,
		PivotRoot:   root,
		UIDMappings: uidMap,
		GIDMappings: gidMap,
	}
	pid, err := r.Start()
	if err != nil {
		ins.Close()
		return nil, fmt.Errorf("container: failed to start container %v", err)
	}

	c := &container{
		pid:    pid,
		socket: newSocket(ins),
	}

	// set configuration and check if container creation successful
	if err = c.conf(&containerConfig{
		Cred: b.CredGenerator != nil,
	}); err != nil {
		c.Destroy()
		return nil, err
	}

	return c, nil
}

// Destroy kill the container process (with its children)
// if stderr enabled, collect the output as error
func (c *container) Destroy() error {
	// close socket (abort any ongoing command)
	c.socket.Close()

	// wait commands terminates
	c.mu.Lock()
	defer c.mu.Unlock()

	// kill process
	var wstatus unix.WaitStatus
	unix.Kill(c.pid, unix.SIGKILL)
	// wait for container process to exit
	_, err := unix.Wait4(c.pid, &wstatus, 0, nil)
	for err == unix.EINTR {
		_, err = unix.Wait4(c.pid, &wstatus, 0, nil)
	}
	return err
}

// exec prepares executable
func (b *Builder) exec() (*os.File, error) {
	if b.ExecFile != nil {
		return b.ExecFile, nil
	}
	return OpenCurrentExec()
}

// OpenCurrentExec opens current executable (/proc/self/exe)
func OpenCurrentExec() (*os.File, error) {
	return os.Open(currentExec)
}

// newPassCredSocketPair creates socket pair and let the first socket to receive credential information
func newPassCredSocketPair() (*unixsocket.Socket, *unixsocket.Socket, error) {
	ins, outs, err := unixsocket.NewSocketPair()
	if err != nil {
		return nil, nil, err
	}
	if err = ins.SetPassCred(1); err != nil {
		ins.Close()
		outs.Close()
		return nil, nil, err
	}
	return ins, outs, nil
}

func getIDMapping(cred *syscall.Credential) ([]syscall.SysProcIDMap, []syscall.SysProcIDMap) {
	uidMap := []syscall.SysProcIDMap{
		{
			ContainerID: 0,
			HostID:      os.Geteuid(),
			Size:        1,
		},
		{
			ContainerID: containerUID,
			HostID:      int(cred.Uid),
			Size:        1,
		},
	}

	gidMap := []syscall.SysProcIDMap{
		{
			ContainerID: 0,
			HostID:      os.Getegid(),
			Size:        1,
		},
		{
			ContainerID: containerGID,
			HostID:      int(cred.Gid),
			Size:        1,
		},
	}

	return uidMap, gidMap
}
