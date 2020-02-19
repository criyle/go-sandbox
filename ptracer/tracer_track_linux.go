package ptracer

import (
	"context"
	"fmt"
	"runtime"
	"time"

	unix "golang.org/x/sys/unix"

	"github.com/criyle/go-sandbox/pkg/seccomp"
	"github.com/criyle/go-sandbox/types"
)

// Trace starts new goroutine and trace runner with ptrace
func (t *Tracer) Trace(c context.Context) <-chan types.Result {
	result := make(chan types.Result, 1)
	go func() {
		result <- t.TraceRun(c)
	}()
	return result
}

// TraceRun start and traces all child process by runner in the calling goroutine
// parameter done used to cancel work, start is used notify child starts
func (t *Tracer) TraceRun(c context.Context) (result types.Result) {
	var (
		status  = types.StatusNormal
		wstatus unix.WaitStatus      // wait4 wait status
		rusage  unix.Rusage          // wait4 rusage
		traced  = make(map[int]bool) // store all process that have set ptrace options
		execved = false              // store whether the runner process have successfully execvd
		pid     int                  // store pid of wait4 result
		sTime   = time.Now()         // records start time for trace process
		fTime   time.Time            // records finish time for execve
	)

	// ptrace is thread based (kernel proc)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Start the runner
	pgid, err := t.Runner.Start()
	t.Handler.Debug("tracer started: ", pgid, err)
	if err != nil {
		t.Handler.Debug("start tracee failed: ", err)
		result.Status = types.StatusRunnerError
		result.Error = err.Error()
		return
	}

	cc, cancel := context.WithCancel(c)
	defer cancel()

	// handle cancelation
	go func() {
		<-cc.Done()
		killAll(pgid)
	}()

	// handler potential panic and tle
	// also ensure processes was well terminated
	defer func() {
		if err := recover(); err != nil {
			t.Handler.Debug("panic: ", err)
			result.Status = types.StatusRunnerError
			result.Error = fmt.Sprintf("%v", err)
		}
		// kill all tracee upon return
		killAll(pgid)
		collectZombie(pgid)
		result.SetUpTime = fTime.Sub(sTime)
		result.RunningTime = time.Since(fTime)
	}()

	// ptrace pool loop
	for {
		if execved {
			// Wait for all child in the process group
			pid, err = unix.Wait4(-pgid, &wstatus, unix.WALL, &rusage)
		} else {
			// Ensure the process have called setpgid
			pid, err = unix.Wait4(pgid, &wstatus, unix.WALL, &rusage)
		}
		if err != nil {
			t.Handler.Debug("wait4 failed: ", err)
			result.Status = types.StatusRunnerError
			result.Error = err.Error()
			return
		}
		t.Handler.Debug("------ ", pid, " ------")

		if pid == pgid {
			// update resource usage and check against limits
			userTime := time.Duration(rusage.Utime.Nano()) // ns
			userMem := types.Size(rusage.Maxrss << 10)     // bytes

			// check tle / mle
			if userTime > t.Limit.TimeLimit {
				status = types.StatusTimeLimitExceeded
			}
			if userMem > t.Limit.MemoryLimit {
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
		}

		// check process status
		switch {
		case wstatus.Exited():
			delete(traced, pid)
			t.Handler.Debug("process exited: ", pid, wstatus.ExitStatus())
			if pid == pgid {
				if execved {
					result.ExitStatus = wstatus.ExitStatus()
					if result.ExitStatus == 0 {
						result.Status = types.StatusNormal
					} else {
						result.Status = types.StatusNonzeroExitStatus
					}
					return
				}
				result.Status = types.StatusRunnerError
				result.Error = "child process exit before execve"
				return
			}

		case wstatus.Signaled():
			sig := wstatus.Signal()
			t.Handler.Debug("ptrace signaled: ", sig)
			if pid == pgid {
				delete(traced, pid)
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
			unix.PtraceCont(pid, int(sig))

		case wstatus.Stopped():
			// Set option if the process is newly forked
			if !traced[pid] {
				t.Handler.Debug("set ptrace option for", pid)
				traced[pid] = true
				// Ptrace set option valid if the tracee is stopped
				err = setPtraceOption(pid)
				if err != nil {
					result.Status = types.StatusRunnerError
					result.Error = err.Error()
					return
				}
			}

			// Check stop signal, if trap then check seccomp
			if stopSig := wstatus.StopSignal(); stopSig == unix.SIGTRAP {
				switch trapCause := wstatus.TrapCause(); trapCause {
				case unix.PTRACE_EVENT_SECCOMP:
					if execved {
						// give the customized handle for syscall
						err := t.handleTrap(pid)
						if err != nil {
							result.Status = types.StatusDisallowedSyscall
							result.Error = err.Error()
							return
						}
					} else {
						t.Handler.Debug("ptrace seccomp before execve (should be the execve syscall)")
					}

				case unix.PTRACE_EVENT_CLONE:
					t.Handler.Debug("ptrace stop clone")
				case unix.PTRACE_EVENT_VFORK:
					t.Handler.Debug("ptrace stop vfork")
				case unix.PTRACE_EVENT_FORK:
					t.Handler.Debug("ptrace stop fork")
				case unix.PTRACE_EVENT_EXEC:
					// forked tracee have successfully called execve
					if !execved {
						fTime = time.Now()
						execved = true
					}
					t.Handler.Debug("ptrace stop exec")

				default:
					t.Handler.Debug("ptrace unexpected trap cause: ", trapCause)
				}
				unix.PtraceCont(pid, 0)
			} else {
				// check if cpu rlimit hit
				switch stopSig {
				case unix.SIGXCPU:
					status = types.StatusTimeLimitExceeded
				case unix.SIGXFSZ:
					status = types.StatusOutputLimitExceeded
				}
				if status != types.StatusNormal {
					result.Status = status
					return
				}
				// Likely encountered SIGSEGV (segment violation)
				// Or compiler child exited
				if stopSig != unix.SIGSTOP {
					t.Handler.Debug("ptrace unexpected stop signal: ", stopSig)
				}
				t.Handler.Debug("ptrace stopped")
				unix.PtraceCont(pid, int(stopSig))
			}
		}
	}
}

// handleTrap handles the seccomp trap including the custom handle
func (t *Tracer) handleTrap(pid int) error {
	t.Handler.Debug("seccomp traced")
	msg, err := unix.PtraceGetEventMsg(pid)
	if err != nil {
		t.Handler.Debug("PtraceGetEventMsg failed:", err)
		return err
	}
	switch int16(msg) {
	case seccomp.MsgDisallow:
		ctx, err := getTrapContext(pid)
		if err != nil {
			t.Handler.Debug("getTrapContext failed:", err)
			return err
		}
		syscallName, err := t.Handler.GetSyscallName(ctx)
		t.Handler.Debug("disallowed syscall: ", ctx.SyscallNo(), syscallName, err)
		return t.Handler.HandlerDisallow(syscallName)

	case seccomp.MsgHandle:
		if t.Handler != nil {
			ctx, err := getTrapContext(pid)
			if err != nil {
				return err
			}
			act := t.Handler.Handle(ctx)

			switch act {
			case TraceBan:
				// Set the syscallno to -1 and return value into register to skip syscall.
				// https://www.kernel.org/doc/Documentation/prctl/pkg/seccomp_filter.txt
				return ctx.skipSyscall()

			case TraceKill:
				return types.StatusDisallowedSyscall
			}
		}

	default:
		// undefined seccomp message, possible set up filter wrong
		t.Handler.Debug("unknown seccomp trap message: ", msg)
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
		if _, err := unix.Wait4(-pgid, &wstatus, unix.WALL|unix.WNOHANG, nil); err != nil {
			break
		}
	}
}
