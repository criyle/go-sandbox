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

	log.Println("Strart trace pid: ", pid)

	// store all tracee process pid existence
	pids := make(map[int]bool)
	//rootPid := pid

	// kill all tracee according to pids
	killAll := func() {
		for p := range pids {
			unix.Kill(p, unix.SIGKILL)
		}
	}

	// kill all tracee upon return
	defer func() {
		killAll()
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

	// trace unixs
	for {
		var wstatus unix.WaitStatus
		var rusage unix.Rusage

		// Wait for all child
		pid, err := unix.Wait4(-1, &wstatus, unix.WALL, &rusage)
		if err != nil {
			log.Fatalln("Wait4 fatal: ", err)
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

		if wstatus.Exited() {
			delete(pids, pid)
			log.Println("Exited", pid, wstatus.ExitStatus())
			break
		}
		if wstatus.Signaled() {
			sig := wstatus.Signal()
			log.Println("Signal", sig)
			switch sig {
			case unix.SIGKILL:
				delete(pids, pid)
				log.Println("Killed")
				continue
			case unix.SIGSYS:
				delete(pids, pid)
				log.Println("Blocked syscall")
			default:
				delete(pids, pid)
				continue
			}
		}
		if wstatus.Stopped() {
			if wstatus.StopSignal() == unix.SIGTRAP {
				switch cause := wstatus.TrapCause(); cause {
				case unix.PTRACE_EVENT_SECCOMP:
					log.Println("Seccomp Traced")
					_, err := unix.PtraceGetEventMsg(pid)
					if err != nil {
						log.Fatalln(err)
					}

					// give the customized handle for syscall
					act, err := r.handleTrap(pid)
					if err != nil {
						return nil, err
					}

					switch act {
					case TraceAllow:
						// do nothing
					case TraceBan:
						// TODO: action according to handler soft ban
					case TraceKill:
						killAll()
					}

				case unix.PTRACE_EVENT_CLONE:
					log.Println("Ptrace stop clone")

				case unix.PTRACE_EVENT_VFORK:
					log.Println("Ptrace stop vfork")

				case unix.PTRACE_EVENT_FORK:
					log.Println("Ptrace stop fork")

				case unix.PTRACE_EVENT_EXEC:
					log.Println("Ptrace stop exec")

				default:
					log.Println("Ptrace trap cause: ", cause, wstatus)
				}
			} else {
				log.Println("Ptrace stop signal: ", wstatus.StopSignal())
			}
		}

		// continue execution
		unix.PtraceCont(pid, 0)
	}
	// TODO: finish resource consumption result
	return &rt, nil
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

func (r *Tracer) handleTrap(pid int) (TraceAction, error) {
	if r.TraceHandle != nil {
		context, err := getTrapContext(pid)
		if err != nil {
			return TraceKill, err
		}
		return r.TraceHandle(context), nil
	}
	return TraceAllow, nil
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
