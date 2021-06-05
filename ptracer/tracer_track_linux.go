package ptracer

import (
	"context"
	"fmt"
	"runtime"
	"time"

	unix "golang.org/x/sys/unix"

	"github.com/criyle/go-sandbox/runner"
)

// Trace start and traces all child process by runner in the calling goroutine
// parameter done used to cancel work, start is used notify child starts
func (t *Tracer) Trace(c context.Context) (result runner.Result) {
	// ptrace is thread based (kernel proc)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Start the runner
	pgid, err := t.Runner.Start()
	t.Handler.Debug("tracer started: ", pgid, err)
	if err != nil {
		t.Handler.Debug("start tracee failed: ", err)
		result.Status = runner.StatusRunnerError
		result.Error = err.Error()
		return
	}
	return t.trace(c, pgid)
}

func (t *Tracer) trace(c context.Context, pgid int) (result runner.Result) {
	cc, cancel := context.WithCancel(c)
	defer cancel()

	// handle cancelation
	go func() {
		<-cc.Done()
		killAll(pgid)
	}()

	sTime := time.Now()
	ph := newPtraceHandle(t, pgid)

	// handler potential panic and tle
	// also ensure processes was well terminated
	defer func() {
		if err := recover(); err != nil {
			t.Handler.Debug("panic: ", err)
			result.Status = runner.StatusRunnerError
			result.Error = fmt.Sprintf("%v", err)
		}
		// kill all tracee upon return
		killAll(pgid)
		collectZombie(pgid)
		if !ph.fTime.IsZero() {
			result.SetUpTime = ph.fTime.Sub(sTime)
			result.RunningTime = time.Since(ph.fTime)
		}
	}()

	// ptrace pool loop
	for {
		var (
			wstatus unix.WaitStatus // wait4 wait status
			rusage  unix.Rusage     // wait4 rusage
			pid     int             // store pid of wait4 result
			err     error
		)
		if ph.execved {
			// Wait for all child in the process group
			pid, err = unix.Wait4(-pgid, &wstatus, unix.WALL, &rusage)
		} else {
			// Ensure the process have called setpgid
			pid, err = unix.Wait4(pgid, &wstatus, unix.WALL, &rusage)
		}
		if err == unix.EINTR {
			t.Handler.Debug("wait4 EINTR")
			continue
		}
		if err != nil {
			t.Handler.Debug("wait4 failed: ", err)
			result.Status = runner.StatusRunnerError
			result.Error = err.Error()
			return
		}
		t.Handler.Debug("------ ", pid, " ------")

		// update rusage
		if pid == pgid {
			userTime, userMem, curStatus := t.checkUsage(rusage)
			result.Status = curStatus
			result.Time = userTime
			result.Memory = userMem
			if curStatus != runner.StatusNormal {
				return
			}
		}

		status, exitStatus, errStr, finished := ph.handle(pid, wstatus)
		if finished || status != runner.StatusNormal {
			result.Status = status
			result.ExitStatus = exitStatus
			result.Error = errStr
			return
		}
	}
}

func (t *Tracer) checkUsage(rusage unix.Rusage) (time.Duration, runner.Size, runner.Status) {
	status := runner.StatusNormal
	// update resource usage and check against limits
	userTime := time.Duration(rusage.Utime.Nano()) // ns
	userMem := runner.Size(rusage.Maxrss << 10)    // bytes

	// check tle / mle
	if userTime > t.Limit.TimeLimit {
		status = runner.StatusTimeLimitExceeded
	}
	if userMem > t.Limit.MemoryLimit {
		status = runner.StatusMemoryLimitExceeded
	}
	return userTime, userMem, status
}

type ptraceHandle struct {
	*Tracer
	pgid    int
	traced  map[int]bool
	execved bool
	fTime   time.Time
}

func newPtraceHandle(t *Tracer, pgid int) *ptraceHandle {
	return &ptraceHandle{t, pgid, make(map[int]bool), false, time.Time{}}
}

func (ph *ptraceHandle) handle(pid int, wstatus unix.WaitStatus) (status runner.Status, exitStatus int, errStr string, finished bool) {
	status = runner.StatusNormal
	// check process status
	switch {
	case wstatus.Exited():
		delete(ph.traced, pid)
		ph.Handler.Debug("process exited: ", pid, wstatus.ExitStatus())
		if pid == ph.pgid {
			finished = true
			if ph.execved {
				exitStatus = wstatus.ExitStatus()
				if exitStatus == 0 {
					status = runner.StatusNormal
				} else {
					status = runner.StatusNonzeroExitStatus
				}
				return
			}
			status = runner.StatusRunnerError
			errStr = "child process exit before execve"
			return
		}

	case wstatus.Signaled():
		sig := wstatus.Signal()
		ph.Handler.Debug("ptrace signaled: ", sig)
		if pid == ph.pgid {
			delete(ph.traced, pid)
			switch sig {
			case unix.SIGXCPU, unix.SIGKILL:
				status = runner.StatusTimeLimitExceeded
			case unix.SIGXFSZ:
				status = runner.StatusOutputLimitExceeded
			case unix.SIGSYS:
				status = runner.StatusDisallowedSyscall
			default:
				status = runner.StatusSignalled
			}
			exitStatus = int(sig)
			return
		}
		unix.PtraceCont(pid, int(sig))

	case wstatus.Stopped():
		// Set option if the process is newly forked
		if !ph.traced[pid] {
			ph.Handler.Debug("set ptrace option for", pid)
			ph.traced[pid] = true
			// Ptrace set option valid if the tracee is stopped
			if err := setPtraceOption(pid); err != nil {
				status = runner.StatusRunnerError
				errStr = err.Error()
				return
			}
		}

		stopSig := wstatus.StopSignal()
		// Check stop signal, if trap then check seccomp
		switch stopSig {
		case unix.SIGTRAP:
			switch trapCause := wstatus.TrapCause(); trapCause {
			case unix.PTRACE_EVENT_SECCOMP:
				if ph.execved {
					// give the customized handle for syscall
					err := ph.handleTrap(pid)
					if err != nil {
						status = runner.StatusDisallowedSyscall
						errStr = err.Error()
						return
					}
				} else {
					ph.Handler.Debug("ptrace seccomp before execve (should be the execve syscall)")
				}

			case unix.PTRACE_EVENT_CLONE:
				ph.Handler.Debug("ptrace stop clone")
			case unix.PTRACE_EVENT_VFORK:
				ph.Handler.Debug("ptrace stop vfork")
			case unix.PTRACE_EVENT_FORK:
				ph.Handler.Debug("ptrace stop fork")
			case unix.PTRACE_EVENT_EXEC:
				// forked tracee have successfully called execve
				if !ph.execved {
					ph.fTime = time.Now()
					ph.execved = true
				}
				ph.Handler.Debug("ptrace stop exec")

			default:
				ph.Handler.Debug("ptrace unexpected trap cause: ", trapCause)
			}
			unix.PtraceCont(pid, 0)
			return

		// check if cpu rlimit hit
		case unix.SIGXCPU:
			status = runner.StatusTimeLimitExceeded
		case unix.SIGXFSZ:
			status = runner.StatusOutputLimitExceeded
		}
		if status != runner.StatusNormal {
			return
		}
		// Likely encountered SIGSEGV (segment violation)
		// Or compiler child exited
		if stopSig != unix.SIGSTOP {
			ph.Handler.Debug("ptrace unexpected stop signal: ", stopSig)
		}
		ph.Handler.Debug("ptrace stopped")
		unix.PtraceCont(pid, int(stopSig))
	}
	return
}

// handleTrap handles the seccomp trap including the custom handle
func (ph *ptraceHandle) handleTrap(pid int) error {
	ph.Handler.Debug("seccomp traced")
	// msg, err := unix.PtraceGetEventMsg(pid)
	// if err != nil {
	// 	t.Handler.Debug("PtraceGetEventMsg failed:", err)
	// 	return err
	// }
	if ph.Handler != nil {
		ctx, err := getTrapContext(pid)
		if err != nil {
			return err
		}
		act := ph.Handler.Handle(ctx)

		switch act {
		case TraceBan:
			// Set the syscallno to -1 and return value into register to skip syscall.
			// https://www.kernel.org/doc/Documentation/prctl/pkg/seccomp_filter.txt
			return ctx.skipSyscall()

		case TraceKill:
			return runner.StatusDisallowedSyscall
		}
	}
	return nil
}

// set Ptrace option that set up seccomp, exit kill and all mult-process actions
func setPtraceOption(pid int) error {
	const ptraceFlags = unix.PTRACE_O_TRACESECCOMP | unix.PTRACE_O_EXITKILL | unix.PTRACE_O_TRACEFORK |
		unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_TRACEVFORK
	return unix.PtraceSetOptions(pid, ptraceFlags)
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
		if _, err := unix.Wait4(-pgid, &wstatus, unix.WALL|unix.WNOHANG, nil); err != unix.EINTR && err != nil {
			break
		}
	}
}
