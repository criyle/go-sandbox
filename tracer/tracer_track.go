package tracer

import (
	"log"
	"runtime"
	"time"

	tracee "github.com/criyle/go-judger/tracee"
	libseccomp "github.com/seccomp/libseccomp-golang"
	unix "golang.org/x/sys/unix"
)

// StartTrace strat the process and trace it
func (r *Tracer) StartTrace() (result *TraceResult, err error) {
	// handle potential panic
	defer func() {
		if r := recover(); r != nil {
			log.Fatal(err)
			err = TraceCodeFatal
		}
	}()

	// Ptrace require running at the same OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// make sure parameter valid
	r.verify()

	// build seccomp filter
	filter, err := r.buildFilter()
	if err != nil {
		return
	}

	tr := r.getTraceeRunner(filter)

	// run in restricted mode
	pid, err := tr.Start()
	if err != nil {
		return
	}

	r.println("Strart trace pid: ", pid)

	// store all tracee process pid existence
	pids := make(map[int]bool)
	rootPid := pid

	// kill all tracee according to pids
	killAll := func() {
		for p := range pids {
			unix.Kill(p, unix.SIGKILL)
		}
	}

	// kill all tracee upon return
	defer func() {
		killAll()
		// collect zombies
		for {
			var wstatus unix.WaitStatus
			if _, err := unix.Wait4(-1, &wstatus, unix.WALL|unix.WNOWAIT, nil); err != nil {
				break
			}
		}
	}()

	// Set real time limit, kill process after it
	tle := false
	timer := time.AfterFunc(time.Duration(int64(r.RealTimeLimit)*1e9), func() {
		tle = true
		killAll()
	})
	defer timer.Stop()

	// Trace result
	var rt TraceResult

	// If forked tracee execved, this syscall should not be handled
	execved := false

	// trace unixs
	for {
		// Wait4 return values
		var wstatus unix.WaitStatus
		var rusage unix.Rusage

		// Wait for all child
		pid, err := unix.Wait4(-1, &wstatus, unix.WALL, &rusage)
		if err != nil {
			r.println("Wait4 failed: ", err)
			break
		}
		// Set option if the process is newly forked
		if !pids[pid] {
			pids[pid] = true
			// Ptrace set option valid if the tracee is stopped
			err = setPtraceOption(pid)
			if err != nil {
				return nil, err
			}
		}

		// Update resource usage
		rt.UserTime = uint64(rusage.Utime.Sec*1e3 + rusage.Utime.Usec/1e3) // ms
		rt.UserMem = uint64(rusage.Maxrss)

		// check tle / mle
		if rt.UserTime > r.TimeLimit*1e3 {
			return nil, TraceCodeTLE
		}
		if rt.UserMem > r.MemoryLimit<<10 {
			return nil, TraceCodeMLE
		}

		// check process status
		switch {
		case wstatus.Exited():
			delete(pids, pid)
			r.println("Exited", pid, wstatus.ExitStatus())
			if pid == rootPid {
				if execved {
					break
				}
				return nil, TraceCodeFatal
			}
			continue

		case wstatus.Signaled():
			sig := wstatus.Signal()
			r.println("Signal", sig)
			if pid == rootPid {
				switch sig {
				case unix.SIGXCPU:
					return nil, TraceCodeTLE
				case unix.SIGXFSZ:
					return nil, TraceCodeOLE
				case unix.SIGSYS:
					return nil, TraceCodeBan
				default:
					return nil, TraceCodeRE
				}
			} else {
				delete(pids, pid)
				continue
			}

		case wstatus.Stopped():
			if stopSig := wstatus.StopSignal(); stopSig == unix.SIGTRAP {
				switch cause := wstatus.TrapCause(); cause {
				case unix.PTRACE_EVENT_SECCOMP:
					if execved {
						// give the customized handle for syscall
						err := r.handleTrap(pid)
						if err != nil {
							return nil, err
						}
					}

				case unix.PTRACE_EVENT_CLONE:
					r.println("Ptrace stop clone")
				case unix.PTRACE_EVENT_VFORK:
					r.println("Ptrace stop vfork")
				case unix.PTRACE_EVENT_FORK:
					r.println("Ptrace stop fork")
				case unix.PTRACE_EVENT_EXEC:
					// forked tracee have successfully called execve
					execved = true
					r.println("Ptrace stop exec")

				default:
					r.println("Unexpected ptrace trap cause: ", cause)
				}
			} else {
				r.println("Unexpected ptrace stop signal: ", stopSig)
			}
		}

		// continue execution
		unix.PtraceCont(pid, 0)
	}
	return &rt, nil
}

// println only print when debug flag is on
func (r *Tracer) println(v ...interface{}) {
	if r.Debug {
		log.Println(v...)
	}
}

func (r *Tracer) verify() {
	if r.RealTimeLimit < r.TimeLimit {
		r.RealTimeLimit = r.TimeLimit + 2
	}
	if r.StackLimit > r.MemoryLimit {
		r.StackLimit = r.MemoryLimit
	}
	// make sure allow, trace no duplicate
	tracedMap := make(map[string]bool)
	for _, s := range r.Trace {
		tracedMap[s] = true
	}
	allow := make([]string, 0, len(r.Allow))
	for _, s := range r.Allow {
		if !tracedMap[s] {
			allow = append(allow, s)
		}
	}
	r.Allow = allow
}

// handleTrap handles the seccomp trap including the custom handle
func (r *Tracer) handleTrap(pid int) error {
	r.println("Seccomp Traced")
	msg, err := unix.PtraceGetEventMsg(pid)
	if err != nil {
		r.println(err)
	}
	switch int16(msg) {
	case msgDisallow:
		ctx, err := getTrapContext(pid)
		if err != nil {
			r.println(err)
		} else {
			syscallNo := ctx.SyscallNo()
			syscallName, err := libseccomp.ScmpSyscall(syscallNo).GetName()
			r.println("disallowed syscall: ", syscallNo, syscallName, err)
		}

	case msgHandle:
		if r.TraceHandle != nil {
			ctx, err := getTrapContext(pid)
			if err != nil {
				return err
			}
			act := r.TraceHandle(ctx)

			switch act {
			case TraceBan:
				// https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt
				// Set the syscallno to -1 and return value into register
				err := ctx.skipSyscall()
				if err != nil {
					return err
				}

			case TraceKill:
				return TraceCodeBan
			}
		}

	default:
		r.println("unknown message: ", msg)
	}

	return nil
}

func setPtraceOption(pid int) error {
	return unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACESECCOMP|unix.PTRACE_O_EXITKILL|
		unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACEVFORK)
}

func (r *Tracer) getTraceeRunner(filter *libseccomp.ScmpFilter) tracee.Runner {
	tr := tracee.NewRunner()
	tr.TimeLimit = r.TimeLimit
	tr.RealTimeLimit = r.RealTimeLimit
	tr.MemoryLimit = r.MemoryLimit
	tr.OutputLimit = r.OutputLimit
	tr.StackLimit = r.StackLimit

	tr.Args = r.Args
	tr.Env = r.Env

	tr.InputFileName = r.InputFileName
	tr.OutputFileName = r.OutputFileName
	tr.ErrorFileName = r.ErrorFileName

	tr.WorkPath = r.WorkPath

	tr.Filter = filter
	return tr
}
