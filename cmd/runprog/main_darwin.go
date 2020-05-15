// Command runprog executes program defined restricted environment including seccomp-ptraced, namespaced and containerized.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
	"time"

	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/pkg/rlimit"
	"github.com/criyle/go-sandbox/runner"
	"golang.org/x/sys/unix"
)

var (
	timeLimit, realTimeLimit, memoryLimit, outputLimit, stackLimit uint64
	inputFileName, outputFileName, errorFileName, workPath         string

	profilePath, result string
	showDetails         bool

	args []string
)

func main() {
	flag.Usage = printUsage
	flag.Uint64Var(&timeLimit, "tl", 1, "Set time limit (in second)")
	flag.Uint64Var(&realTimeLimit, "rtl", 0, "Set real time limit (in second)")
	flag.Uint64Var(&memoryLimit, "ml", 256, "Set memory limit (in mb)")
	flag.Uint64Var(&outputLimit, "ol", 64, "Set output limit (in mb)")
	flag.Uint64Var(&stackLimit, "sl", 32, "Set stack limit (in mb)")
	flag.StringVar(&inputFileName, "in", "", "Set input file name")
	flag.StringVar(&outputFileName, "out", "", "Set output file name")
	flag.StringVar(&errorFileName, "err", "", "Set error file name")
	flag.StringVar(&workPath, "work-path", "", "Set the work path of the program")
	flag.StringVar(&profilePath, "p", "", "sandbox profile")
	flag.BoolVar(&showDetails, "show-trace-details", false, "Show trace details")
	flag.StringVar(&result, "res", "stdout", "Set the file name for output the result")
	flag.Parse()

	args = flag.Args()
	if len(args) == 0 {
		printUsage()
	}

	if realTimeLimit < timeLimit {
		realTimeLimit = timeLimit + 2
	}
	if stackLimit > memoryLimit {
		stackLimit = memoryLimit
	}
	if workPath == "" {
		workPath, _ = os.Getwd()
	}

	var (
		f   *os.File
		err error
	)
	if result == "stdout" {
		f = os.Stdout
	} else if result == "stderr" {
		f = os.Stderr
	} else {
		f, err = os.Create(result)
		if err != nil {
			debug("Failed to open result file:", err)
			return
		}
		defer f.Close()
	}

	rt, err := start()
	debug(rt, err)

	if rt == nil {
		rt = &runner.Result{
			Status: runner.StatusRunnerError,
		}
	}
	if err == nil && rt.Status != runner.StatusNormal {
		err = rt.Status
	}
	debug("setupTime: ", rt.SetUpTime)
	debug("runningTime: ", rt.RunningTime)
	if err != nil {
		debug(err)
		c, ok := err.(runner.Status)
		if !ok {
			c = runner.StatusRunnerError
		}
		// Handle fatal error from trace
		fmt.Fprintf(f, "%d %d %d %d\n", getStatus(c), int(rt.Time/time.Millisecond), uint64(rt.Memory)>>10, rt.ExitStatus)
		if c == runner.StatusRunnerError {
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(f, "%d %d %d %d\n", 0, int(rt.Time/time.Millisecond), uint64(rt.Memory)>>10, rt.ExitStatus)
	}
}

func start() (*runner.Result, error) {
	var sTime, mTime, fTime time.Time
	sTime = time.Now()
	files, err := prepareFiles(inputFileName, outputFileName, errorFileName)
	if err != nil {
		return nil, err
	}
	defer closeFiles(files)

	var profile string
	if profilePath != "" {
		c, err := ioutil.ReadFile(profilePath)
		if err != nil {
			return nil, fmt.Errorf("profile: %v", err)
		}
		profile = string(c)
	}

	// if not defined, then use the original value
	fds := make([]uintptr, len(files))
	for i, f := range files {
		if f != nil {
			fds[i] = f.Fd()
		} else {
			fds[i] = uintptr(i)
		}
	}

	rlims := rlimit.RLimits{
		CPU:          timeLimit,
		CPUHard:      realTimeLimit,
		FileSize:     outputLimit << 20,
		Data:         memoryLimit << 20,
		AddressSpace: memoryLimit << 20,
		Stack:        stackLimit << 20,
	}

	debug(rlims)
	debug(args)

	r := forkexec.Runner{
		Args:           args,
		Env:            []string{pathEnv},
		RLimits:        rlims.PrepareRLimit(),
		Files:          fds,
		WorkDir:        workPath,
		SandboxProfile: profile,
		SyncFunc: func(pid int) error {
			mTime = time.Now()
			return nil
		},
	}
	pid, err := r.Start()
	if err != nil {
		return nil, err
	}

	defer func() {
		killAll(pid)
		collectZombie(pid)
	}()

	var (
		wstatus syscall.WaitStatus
		rusage  syscall.Rusage
	)
	for {
		_, err = syscall.Wait4(pid, &wstatus, 0, &rusage)
		if err == syscall.EINTR {
			continue
		}
		fTime = time.Now()
		if err != nil {
			return nil, err
		}
		result := runner.Result{
			Status:      runner.StatusNormal,
			Time:        time.Duration(rusage.Utime.Nano()),
			Memory:      runner.Size(rusage.Maxrss), // seems MacOS uses bytes instead of kb
			SetUpTime:   mTime.Sub(sTime),
			RunningTime: fTime.Sub(mTime),
		}
		if uint64(result.Time) > timeLimit*1e9 {
			result.Status = runner.StatusTimeLimitExceeded
		}
		if uint64(result.Memory) > memoryLimit<<20 {
			result.Status = runner.StatusMemoryLimitExceeded
		}

		switch {
		case wstatus.Exited():
			if status := wstatus.ExitStatus(); status != 0 {
				result.Status = runner.StatusNonzeroExitStatus
				return &result, nil
			}

		case wstatus.Signaled():
			sig := wstatus.Signal()
			switch sig {
			case unix.SIGXCPU, unix.SIGKILL:
				result.Status = runner.StatusTimeLimitExceeded
			case unix.SIGXFSZ:
				result.Status = runner.StatusOutputLimitExceeded
			case unix.SIGSYS:
				result.Status = runner.StatusDisallowedSyscall
			default:
				result.Status = runner.StatusSignalled
			}
			result.ExitStatus = int(sig)
			return &result, nil
		}
	}
}

// kill all tracee according to pids
func killAll(pgid int) {
	unix.Kill(-pgid, unix.SIGKILL)
}

// collect died child processes
func collectZombie(pgid int) {
	var wstatus unix.WaitStatus
	for {
		if _, err := unix.Wait4(-pgid, &wstatus, unix.WNOHANG, nil); err != unix.EINTR && err != nil {
			break
		}
	}
}
