package ptracer

import (
	"runtime"
	"time"

	unix "golang.org/x/sys/unix"

	"github.com/criyle/go-sandbox/pkg/seccomp"
	"github.com/criyle/go-sandbox/types"
)

// Trace starts new goroutine and trace runner with ptrace
func (t *Tracer) Trace(done <-chan struct{}) (<-chan types.Result, error) {
	var err error
	result := make(chan types.Result, 1)
	start := make(chan struct{})
	finish := make(chan struct{})

	// run
	go func() {
		defer close(finish)
		ret, err2 := t.TraceRun(done, start)
		err = err2
		result <- ret
	}()

	select {
	case <-start:
	case <-finish:
	}
	return result, err
}

// TraceRun start and traces all child process by runner in the calling goroutine
// parameter done used to cancel work, start is used notify child starts
func (t *Tracer) TraceRun(done <-chan struct{}, start chan<- struct{}) (result types.Result, err error) {
	var (
		wstatus unix.WaitStatus      // wait4 wait status
		rusage  unix.Rusage          // wait4 rusage
		tle     bool                 // whether the timmer triggered due to timeout
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
		result.Status = types.StatusRE
		return result, err
	}

	close(start)
	finish := make(chan struct{})
	defer close(finish)

	// handle cancelation
	go func() {
		select {
		case <-done:
			tle = true
			killAll(pgid)
		case <-finish:
		}
	}()

	// handler potential panic and tle
	// also ensure processes was well terminated
	defer func() {
		if tle {
			err = types.StatusTLE
		}
		if err2 := recover(); err2 != nil {
			t.Handler.Debug(err2)
			err = types.StatusFatal
		}
		// kill all tracee upon return
		killAll(pgid)
		collectZombie(pgid)
		result.SetUpTime = fTime.Sub(sTime)
		result.RunningTime = time.Since(fTime)
	}()

	// trace unixs
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
			return result, types.StatusFatal
		}
		t.Handler.Debug("------ ", pid, " ------")

		status := types.StatusNormal
		if pid == pgid {
			// update resource usage and check against limits
			userTime := uint64(rusage.Utime.Sec*1e3 + rusage.Utime.Usec/1e3) // ms
			userMem := uint64(rusage.Maxrss)                                 // kb

			// check tle / mle
			if userTime > t.Limit.TimeLimit {
				status = types.StatusTLE
			}
			if userMem > t.Limit.MemoryLimit {
				status = types.StatusMLE
			}
			result = types.Result{
				Status:   status,
				UserTime: userTime,
				UserMem:  userMem,
			}
			if status != types.StatusNormal {
				return result, status
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
					return result, nil
				}
				result.Status = types.StatusFatal
				return result, types.StatusFatal
			}

		case wstatus.Signaled():
			sig := wstatus.Signal()
			t.Handler.Debug("ptrace signaled: ", sig)
			if pid == pgid {
				delete(traced, pid)
				switch sig {
				case unix.SIGXCPU, unix.SIGKILL:
					status = types.StatusTLE
				case unix.SIGXFSZ:
					status = types.StatusOLE
				case unix.SIGSYS:
					status = types.StatusBan
				default:
					status = types.StatusRE
				}
				result.Status = status
				return result, status
			}
			unix.PtraceCont(pid, int(sig))

		case wstatus.Stopped():
			// Set option if the process is newly forked
			if !traced[pid] {
				t.Handler.Debug("set ptrace option")
				traced[pid] = true
				// Ptrace set option valid if the tracee is stopped
				err = setPtraceOption(pid)
				if err != nil {
					result.Status = types.StatusFatal
					return result, err
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
							result.Status = types.StatusBan
							return result, err
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
					status = types.StatusTLE
				case unix.SIGXFSZ:
					status = types.StatusOLE
				}
				if status != types.StatusNormal {
					result.Status = status
					return result, status
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
				return types.StatusBan
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
