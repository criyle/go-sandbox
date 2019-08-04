package tracer

import (
	"runtime"
	"time"

	"github.com/criyle/go-judger/types/specs"
	unix "golang.org/x/sys/unix"
)

// MsgDisallow, Msghandle defines the action needed when traped by
// seccomp filter
const (
	MsgDisallow int16 = iota + 1
	MsgHandle
)

// Trace traces all child process that created by runner
// this function should called only once and in the same thread that
// exec tracee
func Trace(handler Handler, runner Runner, limits specs.ResLimit) (result specs.TraceResult, err error) {
	var (
		wstatus unix.WaitStatus         // wait4 wait status
		rusage  unix.Rusage             // wait4 rusage
		tle     bool                    // whether the timmer triggered due to timeout
		traced  = make(map[int]bool)    // store all process that have set ptrace options
		execved = false                 // store whether the runner process have successfully execvd
		pid     int                     // store pid of wait4 result
		sTime   = time.Now().UnixNano() // records start time for trace process
		fTime   int64                   // records finish time for execve
	)

	// ptrace is thread based (kernel proc)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Start the runner
	pgid, err := runner.Start()
	handler.Debug("tracer started: ", pgid, err)
	if err != nil {
		handler.Debug("start tracee failed: ", err)
		result.TraceStatus = specs.TraceCodeRE
		return result, err
	}

	// Set real time limit, kill process after it
	timer := time.AfterFunc(time.Duration(int64(limits.RealTimeLimit)*1e6), func() {
		tle = true
		killAll(pgid)
	})

	// handler potential panic and tle
	// also ensure processes was well terminated
	defer func() {
		timer.Stop()
		if tle {
			err = specs.TraceCodeTLE
		}
		if err2 := recover(); err2 != nil {
			handler.Debug(err2)
			err = specs.TraceCodeFatal
		}
		// kill all tracee upon return
		killAll(pgid)
		collectZombie(pgid)
		result.TraceStat.SetUpTime = fTime - sTime
		result.RunningTime = time.Now().UnixNano() - fTime
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
			handler.Debug("wait4 failed: ", err)
			return result, specs.TraceCodeFatal
		}
		handler.Debug("------ ", pid, " ------")

		status := specs.TraceCodeNormal
		if pid == pgid {
			// update resource usage and check against limits
			userTime := uint64(rusage.Utime.Sec*1e3 + rusage.Utime.Usec/1e3) // ms
			userMem := uint64(rusage.Maxrss)                                 // kb

			// check tle / mle
			if userTime > limits.TimeLimit {
				status = specs.TraceCodeTLE
			}
			if userMem > limits.MemoryLimit {
				status = specs.TraceCodeMLE
			}
			result = specs.TraceResult{
				UserTime:    userTime,
				UserMem:     userMem,
				TraceStatus: status,
			}
			if status != specs.TraceCodeNormal {
				return result, status
			}
		}

		// check process status
		switch {
		case wstatus.Exited():
			delete(traced, pid)
			handler.Debug("process exited: ", pid, wstatus.ExitStatus())
			if pid == pgid {
				if execved {
					result.ExitCode = wstatus.ExitStatus()
					return result, nil
				}
				result.TraceStatus = specs.TraceCodeFatal
				return result, specs.TraceCodeFatal
			}

		case wstatus.Signaled():
			sig := wstatus.Signal()
			handler.Debug("ptrace signaled: ", sig)
			if pid == pgid {
				delete(traced, pid)
				switch sig {
				case unix.SIGXCPU:
					status = specs.TraceCodeTLE
				case unix.SIGXFSZ:
					status = specs.TraceCodeOLE
				case unix.SIGSYS:
					status = specs.TraceCodeBan
				default:
					status = specs.TraceCodeRE
				}
				result.TraceStatus = status
				return result, status
			}
			unix.PtraceCont(pid, int(sig))

		case wstatus.Stopped():
			// Set option if the process is newly forked
			if !traced[pid] {
				handler.Debug("set ptrace option")
				traced[pid] = true
				// Ptrace set option valid if the tracee is stopped
				err = setPtraceOption(pid)
				if err != nil {
					result.TraceStatus = specs.TraceCodeFatal
					return result, err
				}
			}

			// Check stop signal, if trap then check seccomp
			if stopSig := wstatus.StopSignal(); stopSig == unix.SIGTRAP {
				switch trapCause := wstatus.TrapCause(); trapCause {
				case unix.PTRACE_EVENT_SECCOMP:
					if execved {
						// give the customized handle for syscall
						err := handleTrap(handler, pid)
						if err != nil {
							result.TraceStatus = specs.TraceCodeBan
							return result, err
						}
					} else {
						handler.Debug("ptrace seccomp before execve (should be the execve syscall)")
					}

				case unix.PTRACE_EVENT_CLONE:
					handler.Debug("ptrace stop clone")
				case unix.PTRACE_EVENT_VFORK:
					handler.Debug("ptrace stop vfork")
				case unix.PTRACE_EVENT_FORK:
					handler.Debug("ptrace stop fork")
				case unix.PTRACE_EVENT_EXEC:
					// forked tracee have successfully called execve
					if !execved {
						fTime = time.Now().UnixNano()
						execved = true
					}
					handler.Debug("ptrace stop exec")

				default:
					handler.Debug("ptrace unexpected trap cause: ", trapCause)
				}
				unix.PtraceCont(pid, 0)
			} else {
				// check if cpu rlimit hit
				switch stopSig {
				case unix.SIGXCPU:
					status = specs.TraceCodeTLE
				case unix.SIGXFSZ:
					status = specs.TraceCodeOLE
				}
				if status != specs.TraceCodeNormal {
					result.TraceStatus = status
					return result, status
				}
				// Likely encountered SIGSEGV (segment violation)
				// Or compiler child exited
				if stopSig != unix.SIGSTOP {
					handler.Debug("ptrace unexpected stop signal: ", stopSig)
				}
				handler.Debug("ptrace stopped")
				unix.PtraceCont(pid, int(stopSig))
			}
		}
	}
}

// handleTrap handles the seccomp trap including the custom handle
func handleTrap(handler Handler, pid int) error {
	handler.Debug("seccomp traced")
	msg, err := unix.PtraceGetEventMsg(pid)
	if err != nil {
		handler.Debug("PtraceGetEventMsg failed:", err)
		return err
	}
	switch int16(msg) {
	case MsgDisallow:
		ctx, err := getTrapContext(pid)
		if err != nil {
			handler.Debug("getTrapContext failed:", err)
			return err
		}
		syscallName, err := handler.GetSyscallName(ctx)
		handler.Debug("disallowed syscall: ", ctx.SyscallNo(), syscallName, err)
		return handler.HandlerDisallow(syscallName)

	case MsgHandle:
		if handler != nil {
			ctx, err := getTrapContext(pid)
			if err != nil {
				return err
			}
			act := handler.Handle(ctx)

			switch act {
			case TraceBan:
				// Set the syscallno to -1 and return value into register. https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt
				return ctx.skipSyscall()

			case TraceKill:
				return specs.TraceCodeBan
			}
		}

	default:
		// undefined seccomp message, possible set up filter wrong
		handler.Debug("unknown seccomp trap message: ", msg)
	}

	return nil
}

// set Ptrace option that set up seccomp, exit kill and all mult-process actions
func setPtraceOption(pid int) error {
	return unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACESECCOMP|unix.PTRACE_O_EXITKILL|
		unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACEVFORK)
}

// kill all tracee according to pids
func killAll(pgid int) {
	unix.Kill(-pgid, unix.SIGKILL)
}

// collect died child processes
func collectZombie(pgid int) {
	// collect zombies
	for {
		var wstatus unix.WaitStatus
		if _, err := unix.Wait4(-pgid, &wstatus, unix.WALL|unix.WNOWAIT, nil); err != nil {
			break
		}
	}
}
