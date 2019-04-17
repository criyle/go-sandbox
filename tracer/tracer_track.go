package tracer

import (
	"fmt"
	"os"
	"runtime"
	"time"

	secutil "github.com/criyle/go-judger/secutil"
	libseccomp "github.com/seccomp/libseccomp-golang"
	unix "golang.org/x/sys/unix"
)

// StartTrace strat the process and trace it
func (r *Tracer) StartTrace() (result *TraceResult, err error) {
	// handle potential panic
	defer func() {
		if err2 := recover(); err2 != nil {
			r.println(err2)
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
	defer filter.Release()

	bpf, err := secutil.FilterToBPF(filter)
	if err != nil {
		return
	}

	// open input / output / err files
	files, err := r.prepareFiles()
	if err != nil {
		return
	}
	defer closeFiles(files)

	// if not defined, then use the original value
	fds := make([]uintptr, len(files))
	for i, f := range files {
		if f != nil {
			fds[i] = f.Fd()
		} else {
			fds[i] = uintptr(i)
		}
	}
	// get tracee
	tr := r.getTraceeRunner(bpf, fds)

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
		r.println("------ ", pid, " ------")
		// Set option if the process is newly forked
		if !pids[pid] {
			r.println("Set ptrace option: ", pid)
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
			return &rt, TraceCodeTLE
		}
		if rt.UserMem > r.MemoryLimit<<10 {
			return &rt, TraceCodeMLE
		}

		// check process status
		switch {
		case wstatus.Exited():
			delete(pids, pid)
			r.println("Exited", pid, wstatus.ExitStatus())
			if pid == rootPid {
				if execved {
					rt.ExitCode = wstatus.ExitStatus()
					return &rt, nil
				}
				return &rt, TraceCodeFatal
			}
			continue

		case wstatus.Signaled():
			sig := wstatus.Signal()
			r.println("Signal", sig)
			if pid == rootPid {
				switch sig {
				case unix.SIGXCPU:
					return &rt, TraceCodeTLE
				case unix.SIGXFSZ:
					return &rt, TraceCodeOLE
				case unix.SIGSYS:
					return &rt, TraceCodeBan
				default:
					return &rt, TraceCodeRE
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
							return &rt, err
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
				if stopSig != unix.SIGSTOP {
					r.println("Unexpected ptrace stop signal: ", stopSig)
				} else {
					r.println("Ptrace stopped")
				}
			}
		}

		// continue execution
		unix.PtraceCont(pid, 0)
	}
	return &rt, nil
}

// println only print when debug flag is on
func (r *Tracer) println(v ...interface{}) {
	if r.ShowDetails {
		fmt.Fprintln(os.Stderr, v...)
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
			r.println("Disallowed syscall: ", syscallNo, syscallName, err)
		}
		if !r.Unsafe {
			return TraceCodeBan
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
