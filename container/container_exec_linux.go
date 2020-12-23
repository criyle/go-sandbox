package container

import (
	"fmt"
	"syscall"
	"time"

	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/pkg/unixsocket"
	"github.com/criyle/go-sandbox/runner"
)

func (c *containerServer) handleExecve(cmd *execCmd, msg *unixsocket.Msg) error {
	var (
		files    []uintptr
		execFile uintptr
		cred     *syscall.Credential
	)
	if cmd == nil {
		return c.sendErrorReply("execve: no parameter provided")
	}
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
		msg := &unixsocket.Msg{
			Cred: &syscall.Ucred{
				Pid: int32(pid),
				Uid: uint32(syscall.Getuid()),
				Gid: uint32(syscall.Getgid()),
			},
		}
		if err := c.sendReply(&reply{}, msg); err != nil {
			return fmt.Errorf("syncFunc: sendReply %v", err)
		}
		cmd, _, err := c.recvCmd()
		if err != nil {
			return fmt.Errorf("syncFunc: recvCmd %v", err)
		}
		if cmd.Cmd == cmdKill {
			return fmt.Errorf("syncFunc: received kill")
		}
		return nil
	}

	if c.Cred {
		cred = &syscall.Credential{
			Uid:         uint32(c.ContainerUID),
			Gid:         uint32(c.ContainerGID),
			NoSetGroups: true,
		}
	}

	var seccomp *syscall.SockFprog
	if cmd.Seccomp != nil {
		seccomp = cmd.Seccomp.SockFprog()
	}

	r := forkexec.Runner{
		Args:       cmd.Argv,
		Env:        cmd.Env,
		ExecFile:   execFile,
		RLimits:    cmd.RLimits,
		Files:      files,
		WorkDir:    c.WorkDir,
		NoNewPrivs: true,
		DropCaps:   true,
		SyncFunc:   syncFunc,
		Credential: cred,
		CTTY:       cmd.CTTY,
		Seccomp:    seccomp,

		UnshareCgroupAfterSync: true,
	}
	// starts the runner, error is handled same as wait4 to make communication equal
	pid, err := r.Start()
	if err != nil {
		// cannot exists now since host assumes the start will alway work
		err = fmt.Errorf("execve: start: %v", err)
	}
	return c.handleExecveStarted(pid, err)
}

func (c *containerServer) handleExecveStarted(pid int, err error) error {
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
			if _, err := syscall.Wait4(-1, nil, syscall.WNOHANG, nil); err != nil && err != syscall.EINTR {
				break
			}
		}
	}()

	// wait pid if no error encountered for execve
	var wstatus syscall.WaitStatus
	var rusage syscall.Rusage
	if err == nil {
		_, err = syscall.Wait4(pid, &wstatus, 0, &rusage)
		for err == syscall.EINTR {
			_, err = syscall.Wait4(pid, &wstatus, 0, &rusage)
		}
		if err != nil {
			err = fmt.Errorf("execve: wait4: %v", err)
		}
	}
	// sync with kill goroutine
	close(waitDone)

	if err != nil {
		c.sendErrorReply(err.Error())
	} else {
		status := runner.StatusNormal
		userTime := time.Duration(rusage.Utime.Nano()) // ns
		userMem := runner.Size(rusage.Maxrss << 10)    // bytes
		switch {
		case wstatus.Exited():
			exitStatus := wstatus.ExitStatus()
			if exitStatus != 0 {
				status = runner.StatusNonzeroExitStatus
			}
			c.sendReply(&reply{
				ExecReply: &execReply{
					Status:     status,
					ExitStatus: exitStatus,
					Time:       userTime,
					Memory:     userMem,
				},
			}, nil)

		case wstatus.Signaled():
			switch wstatus.Signal() {
			// kill signal treats as TLE
			case syscall.SIGXCPU, syscall.SIGKILL:
				status = runner.StatusTimeLimitExceeded
			case syscall.SIGXFSZ:
				status = runner.StatusOutputLimitExceeded
			case syscall.SIGSYS:
				status = runner.StatusDisallowedSyscall
			default:
				status = runner.StatusSignalled
			}
			c.sendReply(&reply{
				ExecReply: &execReply{
					ExitStatus: int(wstatus.Signal()),
					Status:     status,
					Time:       userTime,
					Memory:     userMem,
				},
			}, nil)

		default:
			c.sendErrorReply("execve: unknown status %v", wstatus)
		}
	}

	// wait for kill msg and reply done for finish
	<-killDone
	return c.sendReply(&reply{}, nil)
}
