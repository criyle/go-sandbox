package daemon

import (
	"fmt"
	"syscall"

	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/pkg/unixsocket"
	"github.com/criyle/go-sandbox/types"
)

func (c *containerServer) handleExecve(cmd *Cmd, msg *unixsocket.Msg) error {
	var (
		files    []uintptr
		execFile uintptr
	)
	if msg != nil {
		files = intSliceToUintptr(msg.Fds)
		// don't leak fds to child
		closeOnExecFds(msg.Fds)
		// release files after execve
		defer closeFds(msg.Fds)
	}

	// if fexecve, then the first fd must be executable
	if cmd.FdExec {
		if len(files) == 0 {
			return fmt.Errorf("execve: expected fexecve fd")
		}
		execFile = files[0]
		files = files[1:]
	}

	syncFunc := func(pid int) error {
		msg2 := &unixsocket.Msg{
			Cred: &syscall.Ucred{
				Pid: int32(pid),
				Uid: uint32(syscall.Getuid()),
				Gid: uint32(syscall.Getgid()),
			},
		}
		if err2 := c.sendReply(&Reply{}, msg2); err2 != nil {
			return fmt.Errorf("syncFunc: sendReply(%v)", err2)
		}
		cmd2, _, err2 := c.recvCmd()
		if err2 != nil {
			return fmt.Errorf("syncFunc: recvCmd(%v)", err2)
		}
		if cmd2.Cmd == cmdKill {
			return fmt.Errorf("syncFunc: recved kill")
		}
		return nil
	}

	r := forkexec.Runner{
		Args:       cmd.Argv,
		Env:        cmd.Envv,
		ExecFile:   execFile,
		RLimits:    cmd.RLmits,
		Files:      files,
		WorkDir:    "/w",
		NoNewPrivs: true,
		DropCaps:   true,
		SyncFunc:   syncFunc,
	}
	// starts the runner, error is handled same as wait4 to make communication equal
	pid, err := r.Start()

	// done is to signal kill goroutine exits
	killDone := make(chan struct{})
	// waitDone is to signal kill goroutine to collect zombies
	waitDone := make(chan struct{})

	// recv kill
	go func() {
		// signal done
		defer close(killDone)
		// msg must be kill
		c.recvCmd()
		// kill all
		syscall.Kill(-1, syscall.SIGKILL)
		// make sure collect zombie does not consume the exit status
		<-waitDone
		// collect zombies
		for {
			if pid, err := syscall.Wait4(-1, nil, syscall.WNOHANG, nil); err != nil || pid <= 0 {
				break
			}
		}
	}()

	// wait pid if no error encoutered for execve
	var wstatus syscall.WaitStatus
	var rusage syscall.Rusage
	if err == nil {
		_, err = syscall.Wait4(pid, &wstatus, 0, &rusage)
	}
	// sync with kill goroutine
	close(waitDone)

	if err != nil {
		c.sendErrorReply("execve: wait4 %v", err)
	} else {
		var status types.Status
		userTime := uint64(rusage.Utime.Sec*1e3 + rusage.Utime.Usec/1e3) // ms
		userMem := uint64(rusage.Maxrss)                                 // kb
		switch {
		case wstatus.Exited():
			exitStatus := wstatus.ExitStatus()
			c.sendReply(&Reply{
				Status:     status,
				ExitStatus: exitStatus,
				UserTime:   userTime,
				UserMem:    userMem,
			}, nil)

		case wstatus.Signaled():
			switch wstatus.Signal() {
			// kill signal treats as TLE
			case syscall.SIGXCPU, syscall.SIGKILL:
				status = types.StatusTLE
			case syscall.SIGXFSZ:
				status = types.StatusOLE
			case syscall.SIGSYS:
				status = types.StatusBan
			default:
				status = types.StatusRE
			}
			c.sendReply(&Reply{
				Status:   status,
				UserTime: userTime,
				UserMem:  userMem,
			}, nil)
		default:
			c.sendErrorReply("execve: unknown status %v", wstatus)
		}
	}
	// wait for kill msg and reply done for finish
	<-killDone
	return c.sendReply(&Reply{}, nil)
}
