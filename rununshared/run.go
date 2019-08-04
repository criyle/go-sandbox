package rununshared

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/criyle/go-judger/forkexec"
	"github.com/criyle/go-judger/seccomp"
	"github.com/criyle/go-judger/types/specs"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

const (
	// UnshareFlags is flags used to create namespaces except NET and IPC
	UnshareFlags = unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWUSER | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP
)

// Start starts the unshared process
func (r *RunUnshared) Start() (rt specs.TraceResult, err error) {
	filter, err := seccomp.BuildFilter(libseccomp.ActKill, libseccomp.ActTrap, r.SyscallAllowed, []string{})
	if err != nil {
		println(err)
		return
	}
	defer filter.Release()

	bpf, err := seccomp.FilterToBPF(filter)
	if err != nil {
		println(err)
		return
	}

	ch := &forkexec.Runner{
		Args:              r.Args,
		Env:               r.Env,
		RLimits:           r.RLimits.PrepareRLimit(),
		Files:             r.Files,
		WorkDir:           r.WorkDir,
		Seccomp:           bpf,
		NoNewPrivs:        true,
		StopBeforeSeccomp: false,
		UnshareFlags:      UnshareFlags,
		Mounts:            r.Mounts,
		PivotRoot:         r.Root,
		DropCaps:          true,
		SyncFunc:          r.SyncFunc,
	}
	return r.Trace(ch)
}

// Trace tracks child processes
func (r *RunUnshared) Trace(runner *forkexec.Runner) (result specs.TraceResult, err error) {
	var (
		wstatus unix.WaitStatus // wait4 wait status
		rusage  unix.Rusage     // wait4 rusage
		tle     = false
		status  = specs.TraceCodeNormal
		sTime   = time.Now().UnixNano() // start time
		fTime   int64                   // finish time for setup
	)

	// Start the runner
	pgid, err := runner.Start()
	r.println("Starts: ", pgid, err)
	if err != nil {
		result.TraceStatus = specs.TraceCodeRE
		return result, err
	}
	// Set real time limit, kill process after it
	timer := time.AfterFunc(time.Duration(int64(r.ResLimits.RealTimeLimit)*1e6), func() {
		tle = true
		killAll(pgid)
	})

	defer func() {
		timer.Stop()
		if tle {
			err = specs.TraceCodeTLE
		}
		// kill all tracee upon return
		killAll(pgid)
		collectZombie(pgid)
		result.TraceStat.SetUpTime = fTime - sTime
		result.RunningTime = time.Now().UnixNano() - fTime
	}()

	// currently, we do not have any way to track mount syscall time usage
	fTime = time.Now().UnixNano()

	for {
		pid, err := unix.Wait4(pgid, &wstatus, unix.WALL, &rusage)
		r.println("wait4: ", wstatus)
		if err != nil {
			return result, specs.TraceCodeFatal
		}

		// update resource usage and check against limits
		userTime := uint64(rusage.Utime.Sec*1e3 + rusage.Utime.Usec/1e3) // ms
		userMem := uint64(rusage.Maxrss)                                 // kb

		// check tle / mle
		if userTime > r.ResLimits.TimeLimit {
			status = specs.TraceCodeTLE
		}
		if userMem > r.ResLimits.MemoryLimit {
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

		switch {
		case wstatus.Exited():
			result.ExitCode = wstatus.ExitStatus()
			return result, nil
		case wstatus.Signaled():
			sig := wstatus.Signal()
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
		case wstatus.Stopped():
			unix.Kill(pid, syscall.SIGCONT)
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
	// collect zombies
	for {
		var wstatus unix.WaitStatus
		if _, err := unix.Wait4(-pgid, &wstatus, unix.WALL|unix.WNOWAIT, nil); err != nil {
			break
		}
	}
}

func (r *RunUnshared) println(v ...interface{}) {
	if r.ShowDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}
