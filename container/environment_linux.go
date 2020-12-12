package container

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
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
	Mounts []mount.Mount

	// WorkDir defines container default work directory (default: /w)
	WorkDir string

	// Stderr defines whether to dup container stderr to stderr for debug
	Stderr io.Writer

	// ExecFile defines executable that called Init, otherwise defer current
	// executable (/proc/self/exe)
	ExecFile string

	// CredGenerator defines a credential generator used to create new container
	CredGenerator CredGenerator

	// Clone flags defines unshare clone flag to create container
	CloneFlags uintptr

	// HostName set container hostname (default: go-sandbox)
	HostName string

	// DomainName set container domainname (default: go-sandbox)
	DomainName string

	// ContainerUID & ContainerGID set the container uid / gid mapping
	ContainerUID int
	ContainerGID int
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
	process *os.Process // underlying container init pid
	socket  *socket     // host - container communication
	mu      sync.Mutex  // lock to avoid race condition
}

// Build creates new environment with underlying container
func (b *Builder) Build() (Environment, error) {
	c, err := b.startContainer()
	if err != nil {
		return nil, err
	}

	// avoid non cinit enabled executable running as container init process
	if err = c.Ping(); err != nil {
		c.Destroy()
		return nil, fmt.Errorf("container: container init not responding to ping %v", err)
	}

	// container mount points
	mounts := b.Mounts
	if len(mounts) == 0 {
		mounts = mount.NewDefaultBuilder().
			WithTmpfs("w", "").   // work dir
			WithTmpfs("tmp", ""). // tmp
			FilterNotExist().Mounts
	}

	// container root directory on the host
	root := b.Root
	if root == "" {
		if root, err = os.Getwd(); err != nil {
			return nil, fmt.Errorf("container: failed to get work directory %v", err)
		}
	}
	workDir := containerWD
	if b.WorkDir != "" {
		workDir = b.WorkDir
	}
	hostName := containerName
	if b.HostName != "" {
		hostName = b.HostName
	}
	domainName := containerName
	if b.DomainName != "" {
		domainName = b.DomainName
	}

	// set configuration and check if container creation successful
	if err = c.conf(&containerConfig{
		WorkDir:       workDir,
		HostName:      hostName,
		DomainName:    domainName,
		ContainerRoot: root,
		Mounts:        mounts,
		Cred:          b.CredGenerator != nil,
		ContainerUID:  b.ContainerUID,
		ContainerGID:  b.ContainerGID,
	}); err != nil {
		c.Destroy()
		return nil, err
	}
	return c, nil
}

func (b *Builder) startContainer() (*container, error) {
	var (
		err            error
		cred           syscall.Credential
		uidMap, gidMap []syscall.SysProcIDMap
	)
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

	// prepare container running credential
	if b.CredGenerator != nil {
		cred = b.CredGenerator.Get()
		uidMap, gidMap = b.getIDMapping(&cred)
	} else {
		uidMap = []syscall.SysProcIDMap{{HostID: os.Geteuid(), Size: 1}}
		gidMap = []syscall.SysProcIDMap{{HostID: os.Getegid(), Size: 1}}
	}

	var cloneFlag uintptr
	if b.CloneFlags == 0 {
		cloneFlag = forkexec.UnshareFlags
	} else {
		cloneFlag = b.CloneFlags & forkexec.UnshareFlags
	}

	args := []string{os.Args[0], initArg}
	if b.ExecFile != "" {
		args[0] = b.ExecFile
	}

	r := exec.Cmd{
		Path:       args[0],
		Args:       args,
		Env:        []string{PathEnv},
		Stderr:     b.Stderr,
		ExtraFiles: []*os.File{outf},
		SysProcAttr: &syscall.SysProcAttr{
			Cloneflags:  cloneFlag,
			UidMappings: uidMap,
			GidMappings: gidMap,
			AmbientCaps: []uintptr{
				unix.CAP_SYS_ADMIN,
			},
		},
	}
	if err = r.Start(); err != nil {
		ins.Close()
		return nil, fmt.Errorf("container: failed to start container %v", err)
	}
	return &container{
		process: r.Process,
		socket:  newSocket(ins),
	}, nil
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
	c.process.Kill()
	_, err := c.process.Wait()
	return err
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

func (b *Builder) getIDMapping(cred *syscall.Credential) ([]syscall.SysProcIDMap, []syscall.SysProcIDMap) {
	cUID := b.ContainerUID
	if cUID == 0 {
		cUID = containerUID
	}

	cGID := b.ContainerGID
	if cGID == 0 {
		cGID = containerGID
	}

	uidMap := []syscall.SysProcIDMap{
		{
			ContainerID: 0,
			HostID:      os.Geteuid(),
			Size:        1,
		},
		{
			ContainerID: cUID,
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
			ContainerID: cGID,
			HostID:      int(cred.Gid),
			Size:        1,
		},
	}

	return uidMap, gidMap
}
