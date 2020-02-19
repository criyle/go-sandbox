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
	start := make(chan struct{})
	finish := make(chan struct{})

	// run
	go func() {
		defer close(finish)
		ret, err2 := r.Trace(c.Done(), start, ch)
		ret.Error = err2.Error()
		result <- ret
	}()

	select {
	case <-start:
	case <-finish:
	}
	return result
}

// Trace tracks child processes
func (r *Runner) Trace(done <-chan struct{}, start chan<- struct{},
	runner *forkexec.Runner) (result types.Result, err error) {
	var (
		wstatus unix.WaitStatus // wait4 wait status
		rusage  unix.Rusage     // wait4 rusage
		tle     = false
		status  = types.StatusNormal
		sTime   = time.Now() // start time
		fTime   time.Time    // finish time for setup
	)

	// Start the runner
	pgid, err := runner.Start()
	r.println("Starts: ", pgid, err)
	if err != nil {
		result.Status = types.StatusRunnerError
		return result, err
	}

	close(start)
	finish := make(chan struct{})
	defer close(finish)

	// handle cancel
	go func() {
		select {
		case <-done:
			tle = true
			killAll(pgid)
		case <-finish:
		}
	}()

	defer func() {
		if tle {
			err = types.StatusTimeLimitExceeded
		}
		// kill all tracee upon return
		killAll(pgid)
		collectZombie(pgid)
		result.SetUpTime = fTime.Sub(sTime)
		result.RunningTime = time.Since(fTime)
	}()

	fTime = time.Now()
loop:
	for {
		_, err := unix.Wait4(pgid, &wstatus, 0, &rusage)
		r.println("wait4: ", wstatus)
		if err != nil {
			return result, types.StatusRunnerError
		}

		// update resource usage and check against limits
		userTime := time.Duration(rusage.Utime.Nano()) // ns
		userMem := types.Size(rusage.Maxrss << 10)     // bytes                             // kb

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
			return result, status
		}

		switch {
		case wstatus.Exited():
			result.ExitStatus = wstatus.ExitStatus()
			return result, nil
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
			break loop
		}
	}
	return result, status
}

// kill all tracee according to pids
func killAll(pgid int) {
	unix.Kill(-pgid, unix.SIGKILL)
}

// collect died child processes
func collectZombie(pgid int) {
	var wstatus unix.WaitStatus
	// collect zombies
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
