package unshare

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/runner"
)

const (
	// UnshareFlags is flags used to create namespaces except NET and IPC
	UnshareFlags = unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWUSER | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP
)

// Run starts the unshared process
func (r *Runner) Run(c context.Context) (result runner.Result) {
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

		UnshareCgroupAfterSync: true,
	}

	var (
		wstatus    unix.WaitStatus // wait4 wait status
		rusage     unix.Rusage     // wait4 rusage
		status     = runner.StatusNormal
		sTime      = time.Now() // start time
		fTime      time.Time    // finish time for setup
		rootDone   bool
		rootStatus runner.Status
		rootExit   int
		cpuUsage   = make(map[int]time.Duration)
		memUsage   = make(map[int]runner.Size)
		totalCPU   time.Duration
		totalMem   runner.Size
	)

	// Start the runner
	pgid, err := ch.Start()
	r.println("Starts: ", pgid, err)
	if err != nil {
		result.Status = runner.StatusRunnerError
		result.Error = err.Error()
		return
	}

	ctx, cancel := context.WithCancel(c)
	defer cancel()

	// handle cancel
	go func() {
		<-ctx.Done()
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
		pid, err := unix.Wait4(-pgid, &wstatus, unix.WALL, &rusage)
		if err == unix.EINTR {
			continue
		}
		if err == unix.ECHILD && rootDone {
			result.Status = rootStatus
			result.ExitStatus = rootExit
			return
		}
		r.println("wait4: ", wstatus)
		if err != nil {
			result.Status = runner.StatusRunnerError
			result.Error = err.Error()
			return
		}

		// update resource usage and check against limits
		userTime := time.Duration(rusage.Utime.Nano()) // ns
		if previous := cpuUsage[pid]; userTime > previous {
			totalCPU += userTime - previous
			cpuUsage[pid] = userTime
		}
		userMem := runner.Size(rusage.Maxrss << 10) // bytes
		if previous := memUsage[pid]; userMem > previous {
			memUsage[pid] = userMem
			// wait4 reports per-process peak RSS rather than a simultaneous
			// process-tree snapshot. Keep the largest observed peak so
			// sequential children do not accumulate into a false MLE.
			if userMem > totalMem {
				totalMem = userMem
			}
		}

		// check tle / mle
		if r.Limit.TimeLimit > 0 && totalCPU > r.Limit.TimeLimit {
			status = runner.StatusTimeLimitExceeded
		}
		if r.Limit.MemoryLimit > 0 && totalMem > r.Limit.MemoryLimit {
			status = runner.StatusMemoryLimitExceeded
		}
		result = runner.Result{
			Status: status,
			Time:   totalCPU,
			Memory: totalMem,
		}
		if status != runner.StatusNormal {
			return
		}

		switch {
		case wstatus.Exited():
			if pid == pgid {
				rootDone = true
				rootExit = wstatus.ExitStatus()
				rootStatus = runner.StatusNormal
				if rootExit != 0 {
					rootStatus = runner.StatusNonzeroExitStatus
				}
			}
			if rootDone {
				// The namespace init process exiting terminates the remaining
				// processes. Drain their wait statuses before returning so their
				// already-accounted resource usage is included.
				continue
			}

		case wstatus.Signaled():
			sig := wstatus.Signal()
			if pid != pgid {
				continue
			}
			rootDone = true
			rootExit = int(sig)
			switch sig {
			case unix.SIGXCPU, unix.SIGKILL:
				rootStatus = runner.StatusTimeLimitExceeded
			case unix.SIGXFSZ:
				rootStatus = runner.StatusOutputLimitExceeded
			case unix.SIGSYS:
				rootStatus = runner.StatusDisallowedSyscall
			default:
				rootStatus = runner.StatusSignalled
			}
			continue
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
		_, err := unix.Wait4(-pgid, &wstatus, unix.WALL, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			break
		}
	}
}

func (r *Runner) println(v ...any) {
	if r.ShowDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}
