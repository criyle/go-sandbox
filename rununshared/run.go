package rununshared

import (
	"fmt"
	"os"
	"time"

	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/pkg/seccomp"
	"github.com/criyle/go-sandbox/types/specs"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

const (
	// UnshareFlags is flags used to create namespaces except NET and IPC
	UnshareFlags = unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWUSER | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP
)

// Start starts the unshared process
func (r *RunUnshared) Start(done <-chan struct{}) (<-chan specs.TraceResult, error) {
	filter, err := seccomp.BuildFilter(libseccomp.ActKill, libseccomp.ActTrap, r.SyscallAllowed, []string{})
	if err != nil {
		println(err)
		return nil, err
	}
	defer filter.Release()

	bpf, err := seccomp.FilterToBPF(filter)
	if err != nil {
		println(err)
		return nil, err
	}

	ch := &forkexec.Runner{
		Args:              r.Args,
		Env:               r.Env,
		ExecFile:          r.ExecFile,
		RLimits:           r.RLimits.PrepareRLimit(),
		Files:             r.Files,
		WorkDir:           r.WorkDir,
		Seccomp:           bpf,
		NoNewPrivs:        true,
		StopBeforeSeccomp: false,
		UnshareFlags:      UnshareFlags,
		Mounts:            r.Mounts,
		HostName:          r.HostName,
		DomainName:        r.DomainName,
		PivotRoot:         r.Root,
		DropCaps:          true,
		SyncFunc:          r.SyncFunc,
	}

	result := make(chan specs.TraceResult, 1)
	start := make(chan struct{})
	finish := make(chan struct{})

	// run
	go func() {
		defer close(finish)
		ret, err2 := r.Trace(done, start, ch)
		err = err2
		result <- ret
	}()

	select {
	case <-start:
	case <-finish:
	}
	return result, err
}

// Trace tracks child processes
func (r *RunUnshared) Trace(done <-chan struct{}, start chan<- struct{},
	runner *forkexec.Runner) (result specs.TraceResult, err error) {
	var (
		wstatus unix.WaitStatus // wait4 wait status
		rusage  unix.Rusage     // wait4 rusage
		tle     = false
		status  = specs.TraceCodeNormal
		sTime   = time.Now() // start time
		fTime   time.Time    // finish time for setup
	)

	// Start the runner
	pgid, err := runner.Start()
	r.println("Starts: ", pgid, err)
	if err != nil {
		result.TraceStatus = specs.TraceCodeRE
		return result, err
	}

	close(start)
	finish := make(chan struct{})
	defer close(finish)

	// handle cancel
	go func() {
		select {
		case <-done:
			tle = true
			killAll(pgid)
		case <-finish:
		}
	}()

	defer func() {
		if tle {
			err = specs.TraceCodeTLE
		}
		// kill all tracee upon return
		killAll(pgid)
		collectZombie(pgid)
		result.SetUpTime = fTime.Sub(sTime).Nanoseconds()
		result.RunningTime = time.Since(fTime).Nanoseconds()
	}()

	fTime = time.Now()
	for {
		_, err := unix.Wait4(pgid, &wstatus, 0, &rusage)
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
			case unix.SIGXCPU, unix.SIGKILL:
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
	}
	return result, status
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

func (r *RunUnshared) println(v ...interface{}) {
	if r.ShowDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}
