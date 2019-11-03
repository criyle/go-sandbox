package daemon

import (
	"fmt"
	"os"
	"sync"

	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/pkg/memfd"
	"github.com/criyle/go-sandbox/pkg/mount"
	"github.com/criyle/go-sandbox/pkg/pipe"
	"github.com/criyle/go-sandbox/pkg/unixsocket"
	"golang.org/x/sys/unix"
)

// Builder builds instance of container masters
type Builder struct {
	// Root is container root mount path, empty uses current work path
	Root string

	// Mounts defines container mount points, empty uses default mounts
	Mounts []mount.SyscallParams

	// Stderr defines whether to collect container stderr output for debug
	Stderr bool

	// ExecFile defines executable that called Init, otherwise defer current
	// executable (/proc/self/exe)
	ExecFile *os.File
}

// Master manages single pre-forked container
type Master struct {
	pid    int                // underlying container init pid
	socket *unixsocket.Socket // master - container communication
	buff   *pipe.Buffer       // collect stderr output from container
	mu     sync.Mutex         // lock to avoid race condition
}

// Build creates new master with underlying container
func (b *Builder) Build() (*Master, error) {
	var (
		err  error
		buff *pipe.Buffer
	)
	// container mount points
	mounts := b.Mounts
	if len(mounts) == 0 {
		if mounts, err = mount.NewBuilder().WithMounts(DefaultMounts).Build(true); err != nil {
			return nil, fmt.Errorf("daemon: failed to build rootfs mount %v", err)
		}
	}
	root := b.Root
	if root == "" {
		if root, err = os.Getwd(); err != nil {
			return nil, fmt.Errorf("daemon: failed to get work directory %v", err)
		}
	}
	// prepare stdin / stdout / stderr
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("daemon: failed to open devNull(%v)", err)
	}
	defer devNull.Close()

	files := make([]uintptr, 0, 4)
	files = append(files, devNull.Fd(), devNull.Fd())
	if b.Stderr {
		buff, err = pipe.NewBuffer(bufferSize)
		if err != nil {
			return nil, fmt.Errorf("daemon: failed to open stderr pipe: %v", err)
		}
		defer buff.W.Close()
		files = append(files, buff.W.Fd())
	} else {
		files = append(files, devNull.Fd())
	}

	// prepare self memfd
	execFile, err := b.exec()
	if err != nil {
		return nil, fmt.Errorf("deamon: %v", err)
	}
	defer execFile.Close()

	// prepare socket
	ins, outs, err := newPassCredSocketPair()
	if err != nil {
		return nil, fmt.Errorf("daemon: failed to create socket: %v", err)
	}
	defer outs.Close()

	outf, err := outs.File()
	if err != nil {
		ins.Close()
		return nil, fmt.Errorf("daemon: failed to dup file outs(%v)", err)
	}
	defer outf.Close()

	files = append(files, uintptr(outf.Fd()))
	r := &forkexec.Runner{
		Args:       []string{os.Args[0], initArg},
		Env:        []string{DefaultPath},
		ExecFile:   execFile.Fd(),
		Files:      files,
		WorkDir:    "/w",
		CloneFlags: forkexec.UnshareFlags,
		Mounts:     mounts,
		HostName:   "daemon",
		DomainName: "daemon",
		PivotRoot:  root,
	}
	pid, err := r.Start()
	if err != nil {
		ins.Close()
		return nil, fmt.Errorf("daemon: failed to execve(%v)", err)
	}
	return &Master{
		pid:    pid,
		socket: ins,
		buff:   buff,
	}, nil
}

// Destroy kill the daemon process (with container)
// if stderr enabled, collect the output as error
func (m *Master) Destroy() error {
	var wstatus unix.WaitStatus
	unix.Kill(m.pid, unix.SIGKILL)
	if _, err := unix.Wait4(m.pid, &wstatus, 0, nil); err != nil {
		return err
	}
	if m.buff != nil {
		<-m.buff.Done
		return fmt.Errorf("destroy: %s", m.buff.Buffer.Bytes())
	}
	return nil
}

// exec prepares executable
func (b *Builder) exec() (*os.File, error) {
	if b.ExecFile != nil {
		return b.ExecFile, nil
	}
	return OpenCurrentExec()
}

// OpenCurrentExec opens current executable and dup it to memfd
func OpenCurrentExec() (*os.File, error) {
	self, err := os.Open(currentExec)
	if err != nil {
		return nil, fmt.Errorf("failed to open %v: %v", currentExec, err)
	}
	defer self.Close()

	execFile, err := memfd.DupToMemfd("daemon", self)
	if err != nil {
		return nil, fmt.Errorf("failed to create memfd: %v", err)
	}
	return execFile, nil
}

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
	if err = outs.SetPassCred(1); err != nil {
		ins.Close()
		outs.Close()
		return nil, nil, err
	}
	return ins, outs, nil
}
