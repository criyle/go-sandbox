// +build linux

package unshare

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/types"
)

const (
	// UnshareFlags is flags used to create namespaces except NET and IPC
	UnshareFlags = unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWUSER | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP
)

// Run starts the unshared process
func (r *Runner) Run(c context.Context) <-chan types.Result {
	ch := &forkexec.Runner{
		Args:       r.Args,
		Env:        r.Env,
		ExecFile:   r.ExecFile,
		RLimits:    r.RLimits,
		Files:      r.Files,
		WorkDir:    r.WorkDir,
		Seccomp:    r.Seccomp.SockFprog(),
		NoNewPrivs: true,
		CloneFlags: UnshareFlags,
		Mounts:     r.Mounts,
		HostName:   r.HostName,
		DomainName: r.DomainName,
		PivotRoot:  r.Root,
		DropCaps:   true,
		SyncFunc:   r.SyncFunc,
	}

	result := make(chan types.Result, 1)
	go func() {
		result <- r.trace(c, ch)
	}()

	return result
}

// Trace tracks child processes
func (r *Runner) trace(c context.Context, runner *forkexec.Runner) (result types.Result) {
	var (
		wstatus unix.WaitStatus // wait4 wait status
		rusage  unix.Rusage     // wait4 rusage
		status  = types.StatusNormal
		sTime   = time.Now() // start time
		fTime   time.Time    // finish time for setup
	)

	// Start the runner
	pgid, err := runner.Start()
	r.println("Starts: ", pgid, err)
	if err != nil {
		result.Status = types.StatusRunnerError
		result.Error = err.Error()
		return
	}

	cc, cancel := context.WithCancel(c)
	defer cancel()

	// handle cancel
	go func() {
		<-cc.Done()
		killAll(pgid)
	}()

	// kill all tracee upon return
	defer func() {
		killAll(pgid)
		collectZombie(pgid)
		result.SetUpTime = fTime.Sub(sTime)
		result.RunningTime = time.Since(fTime)
	}()

	fTime = time.Now()
	for {
		_, err := unix.Wait4(pgid, &wstatus, 0, &rusage)
		r.println("wait4: ", wstatus)
		if err != nil {
			result.Status = types.StatusRunnerError
			result.Error = err.Error()
			return
		}

		// update resource usage and check against limits
		userTime := time.Duration(rusage.Utime.Nano()) // ns
		userMem := types.Size(rusage.Maxrss << 10)     // bytes

		// check tle / mle
		if userTime > r.Limit.TimeLimit {
			status = types.StatusTimeLimitExceeded
		}
		if userMem > r.Limit.MemoryLimit {
			status = types.StatusMemoryLimitExceeded
		}
		result = types.Result{
			Status: status,
			Time:   userTime,
			Memory: userMem,
		}
		if status != types.StatusNormal {
			return
		}

		switch {
		case wstatus.Exited():
			result.Status = types.StatusNormal
			result.ExitStatus = wstatus.ExitStatus()
			if result.ExitStatus != 0 {
				result.Status = types.StatusNonzeroExitStatus
			}
			return

		case wstatus.Signaled():
			sig := wstatus.Signal()
			switch sig {
			case unix.SIGXCPU, unix.SIGKILL:
				status = types.StatusTimeLimitExceeded
			case unix.SIGXFSZ:
				status = types.StatusOutputLimitExceeded
			case unix.SIGSYS:
				status = types.StatusDisallowedSyscall
			default:
				status = types.StatusSignalled
			}
			result.Status = status
			result.ExitStatus = int(sig)
			return
		}
	}
}

// kill all tracee according to pids
func killAll(pgid int) {
	unix.Kill(-pgid, unix.SIGKILL)
}

// collect died child processes
func collectZombie(pgid int) {
	var wstatus unix.WaitStatus
	for {
		if _, err := unix.Wait4(-pgid, &wstatus, unix.WALL|unix.WNOHANG, nil); err != nil {
			break
		}
	}
}

func (r *Runner) println(v ...interface{}) {
	if r.ShowDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}
