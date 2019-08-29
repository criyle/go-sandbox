package deamon

import (
	"fmt"
	"os"

	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/pkg/memfd"
	"github.com/criyle/go-sandbox/pkg/unixsocket"
	"golang.org/x/sys/unix"
)

// Master manages single pre-forked container
type Master struct {
	pid    int                // underlying container init pid
	socket *unixsocket.Socket // master - container communication
}

// New creates new master with underlying container
func New(root string) (*Master, error) {
	// dummy stdin / stdout / stderr
	fnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0666)
	if err != nil {
		return nil, fmt.Errorf("deamon: failed to open devNull(%v)", err)
	}
	defer fnull.Close()

	// prepare self memfd
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, fmt.Errorf("deamon: failed to open /proc/self/exe(%v)", err)
	}
	defer self.Close()

	execFile, err := memfd.DupToMemfd("deamon", self)
	if err != nil {
		return nil, fmt.Errorf("deamon: failed to create memfd(%v)", err)
	}
	defer execFile.Close()

	// prepare socket
	ins, outs, err := unixsocket.NewSocketPair()
	if err != nil {
		return nil, fmt.Errorf("deamon: failed to create socket(%v)", err)
	}
	outf, err := outs.Conn.File()
	if err != nil {
		ins.Conn.Close()
		outs.Conn.Close()
		return nil, fmt.Errorf("deamon: failed to dup file outs(%v)", err)
	}
	defer outf.Close()
	if err = ins.SetPassCred(1); err != nil {
		ins.Conn.Close()
		outs.Conn.Close()
		return nil, fmt.Errorf("deamon: failed to set pass_cred ins(%v)", err)
	}
	if err = outs.SetPassCred(1); err != nil {
		ins.Conn.Close()
		outs.Conn.Close()
		return nil, fmt.Errorf("deamon: failed to set pass_cred outs(%v)", err)
	}

	r := &forkexec.Runner{
		Args:         []string{os.Args[0], initArg},
		Env:          []string{DefaultPath},
		ExecFile:     execFile.Fd(),
		Files:        []uintptr{fnull.Fd(), fnull.Fd(), fnull.Fd(), uintptr(outf.Fd())},
		WorkDir:      "/w",
		UnshareFlags: forkexec.UnshareFlags,
		Mounts:       DefaultMounts,
		HostName:     "deamon",
		DomainName:   "deamon",
		PivotRoot:    root,
	}
	pid, err := r.Start()
	if err != nil {
		ins.Conn.Close()
		outs.Conn.Close()
		return nil, fmt.Errorf("deamon: failed to execve(%v)", err)
	}

	outs.Conn.Close()
	return &Master{pid, ins}, nil
}

// Destroy kill the deamon process (with container)
func (m *Master) Destroy() error {
	var wstatus unix.WaitStatus
	unix.Kill(m.pid, unix.SIGKILL)
	_, err := unix.Wait4(m.pid, &wstatus, 0, nil)
	return err
}
