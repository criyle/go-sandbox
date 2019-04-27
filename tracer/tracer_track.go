package tracer

import (
	"fmt"
	"os"
	"runtime"
	"time"

	unix "golang.org/x/sys/unix"
)

// MsgDisallow, Msghandle defines the action needed when traped by
// seccomp filter
const (
	MsgDisallow int16 = iota + 1
	MsgHandle
)

var (
	// ShowDetails is switch to trun on / off whether to show log message
	ShowDetails bool
	// Unsafe determines whether to terminate tracing when bad syscall caught
	Unsafe bool
)

// Trace traces all child process that created by runner
// this function should called only once and in the same thread that
// exec tracee
func Trace(handler Handler, runners []Runner, limits ResLimit, timeout int64) (results []TraceResult, err error) {
	var (
		wstatus unix.WaitStatus      // wait4 wait status
		rusage  unix.Rusage          // wait4 rusage
		tle     bool                 // whether the timmer triggered due to timeout
		traced  = make(map[int]bool) // store all process that have set ptrace options
		execved = make(map[int]bool) // store whether a runner process have successfully execvd
		pidmap  = make(map[int]int)  // pid -> index map
		running = len(runners)       // total number of remained runner process
	)
	results = make([]TraceResult, len(runners))

	// make this thread exit after trace, ensure no process escaped
	runtime.LockOSThread()

	// Starts all runners
	for i, r := range runners {
		pid, err := r.Start()
		println("tracer started: ", pid, err)
		if err != nil {
			results[i].TraceStatus = TraceCodeRE
			return results, err
		}
		pidmap[pid] = i
	}

	// Set real time limit, kill process after it
	timer := time.AfterFunc(time.Duration(timeout), func() {
		tle = true
		killAll(traced)
	})

	// handler potential panic and tle
	// also ensure processes was well terminated
	defer func() {
		timer.Stop()
		if tle {
			err = TraceCodeTLE
		}
		if err2 := recover(); err2 != nil {
			println(err2)
			err = TraceCodeFatal
		}
		// kill all tracee upon return
		killAll(traced)
		collectZombie()
	}()

	// trace unixs
	for {
		// Wait for all child
		pid, err := unix.Wait4(-1, &wstatus, unix.WALL, &rusage)
		if err != nil {
			println("wait4 failed: ", err)
			return results, TraceCodeFatal
		}
		println("------ ", pid, " ------")
		// Set option if the process is newly forked
		if !traced[pid] {
			println("set ptrace option")
			traced[pid] = true
			// Ptrace set option valid if the tracee is stopped
			err = setPtraceOption(pid)
			if err != nil {
				return results, err
			}
		}

		// update resource usage and check against limits
		userTime := uint(rusage.Utime.Sec*1e3 + rusage.Utime.Usec/1e3) // ms
		userMem := uint(rusage.Maxrss)                                 // kb
		idx, inside := pidmap[pid]                                     // index
		status := TraceCodeNormal                                      // check limit

		// check tle / mle
		if userTime > limits.TimeLimit {
			status = TraceCodeTLE
		}
		if userMem > limits.MemoryLimit {
			status = TraceCodeMLE
		}
		if inside {
			results[idx] = TraceResult{
				UserTime:    userTime,
				UserMem:     userMem,
				TraceStatus: status,
			}
		}
		if status != TraceCodeNormal {
			return results, status
		}

		// check process status
		switch {
		case wstatus.Exited():
			delete(traced, pid)
			println("process exited: ", pid, wstatus.ExitStatus())
			if inside {
				if execved[pid] {
					results[idx].ExitCode = wstatus.ExitStatus()
					if running--; running == 0 {
						return results, nil
					}
				} else {
					results[idx].TraceStatus = TraceCodeFatal
					return results, TraceCodeFatal
				}
			}

		case wstatus.Signaled():
			sig := wstatus.Signal()
			println("ptrace signaled: ", sig)
			if inside {
				switch sig {
				case unix.SIGXCPU:
					status = TraceCodeTLE
				case unix.SIGXFSZ:
					status = TraceCodeOLE
				case unix.SIGSYS:
					status = TraceCodeBan
				default:
					status = TraceCodeRE
				}
				results[idx].TraceStatus = status
				return results, status
			}
			delete(traced, pid)

		case wstatus.Stopped():
			if stopSig := wstatus.StopSignal(); stopSig == unix.SIGTRAP {
				switch trapCause := wstatus.TrapCause(); trapCause {
				case unix.PTRACE_EVENT_SECCOMP:
					if !inside || execved[pid] {
						// give the customized handle for syscall
						err := handleTrap(handler, pid)
						if err != nil {
							if inside {
								results[idx].TraceStatus = TraceCodeBan
							}
							return results, err
						}
					} else {
						println("ptrace seccomp before execve (should be the execve syscall)")
					}

				case unix.PTRACE_EVENT_CLONE:
					println("ptrace stop clone")
				case unix.PTRACE_EVENT_VFORK:
					println("ptrace stop vfork")
				case unix.PTRACE_EVENT_FORK:
					println("ptrace stop fork")
				case unix.PTRACE_EVENT_EXEC:
					// forked tracee have successfully called execve
					execved[pid] = true
					println("ptrace stop exec")

				default:
					println("ptrace unexpected trap cause: ", trapCause)
				}
			} else {
				// Likely encountered SIGSEGV (segment violation)
				if stopSig != unix.SIGSTOP {
					println("ptrace unexpected stop signal: ", stopSig)
					if inside {
						results[idx].TraceStatus = TraceCodeRE
					}
					return results, TraceCodeRE
				}
				println("ptrace stopped")
			}
			unix.PtraceCont(pid, 0)

		default:
			// should never happen
			println("unexpected wait status: ", wstatus)
			unix.PtraceCont(pid, 0)
		}
	}
}

// handleTrap handles the seccomp trap including the custom handle
func handleTrap(handler Handler, pid int) error {
	println("seccomp traced")
	msg, err := unix.PtraceGetEventMsg(pid)
	if err != nil {
		println(err)
		return err
	}
	switch int16(msg) {
	case MsgDisallow:
		ctx, err := getTrapContext(pid)
		if err != nil {
			println(err)
			return err
		}
		if ShowDetails {
			syscallName, err := handler.GetSyscallName(ctx)
			println("disallowed syscall: ", ctx.SyscallNo(), syscallName, err)
		}
		if !Unsafe {
			return TraceCodeBan
		}

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
				return TraceCodeBan
			}
		}

	default:
		// undefined seccomp message, possible set up filter wrong
		println("unknown seccomp trap message: ", msg)
	}

	return nil
}

// set Ptrace option that set up seccomp, exit kill and all mult-process actions
func setPtraceOption(pid int) error {
	return unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACESECCOMP|unix.PTRACE_O_EXITKILL|
		unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACEVFORK)
}

// println only print when debug flag is on
func println(v ...interface{}) {
	if ShowDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}

// kill all tracee according to pids
func killAll(pids map[int]bool) {
	for p := range pids {
		println("kill: ", p)
		unix.Kill(p, unix.SIGKILL)
	}
}

// collect died child processes
func collectZombie() {
	// collect zombies
	for {
		var wstatus unix.WaitStatus
		if p, err := unix.Wait4(-1, &wstatus, unix.WALL|unix.WNOWAIT, nil); err != nil {
			break
		} else {
			println("collect: ", p)
		}
	}
}
