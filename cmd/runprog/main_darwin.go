// Command runprog executes program defined restricted environment including seccomp-ptraced, namespaced and containerized.
package main

import (
	"flag"
	"log"
	"os"
	"syscall"
	"time"

	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/pkg/rlimit"
	"github.com/criyle/go-sandbox/runner"
)

var (
	timeLimit, realTimeLimit, memoryLimit, outputLimit, stackLimit uint64
	inputFileName, outputFileName, errorFileName, workPath         string

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

	ret, err := start()
	log.Println(ret, err)
}

func start() (*runner.Result, error) {
	var sTime, mTime, fTime time.Time
	sTime = time.Now()
	files, err := prepareFiles(inputFileName, outputFileName, errorFileName)
	if err != nil {
		return nil, err
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

	rlims := rlimit.RLimits{
		CPU:          timeLimit,
		CPUHard:      realTimeLimit,
		FileSize:     outputLimit << 20,
		Data:         memoryLimit << 20,
		AddressSpace: memoryLimit << 20,
		Stack:        stackLimit << 20,
	}

	log.Println(rlims)
	log.Println(args)

	r := forkexec.Runner{
		Args:           args,
		Env:            []string{pathEnv},
		RLimits:        rlims.PrepareRLimit(),
		Files:          fds,
		WorkDir:        workPath,
		SandboxProfile: "",
		SyncFunc: func(pid int) error {
			mTime = time.Now()
			return nil
		},
	}
	pid, err := r.Start()
	if err != nil {
		return nil, err
	}
	var (
		wstatus syscall.WaitStatus
		rusage  syscall.Rusage
	)
	_, err = syscall.Wait4(pid, &wstatus, 0, &rusage)
	for err == syscall.EINTR {
		_, err = syscall.Wait4(pid, &wstatus, 0, &rusage)
	}
	fTime = time.Now()
	if err != nil {
		return nil, err
	}
	result := runner.Result{
		Status:      runner.StatusNormal,
		Time:        time.Duration(rusage.Utime.Nano()),
		Memory:      runner.Size(rusage.Maxrss),
		SetUpTime:   mTime.Sub(sTime),
		RunningTime: fTime.Sub(mTime),
	}
	switch {
	case wstatus.Exited():
		if status := wstatus.ExitStatus(); status != 0 {
			result.Status = runner.StatusNonzeroExitStatus
			return &result, nil
		}

	case wstatus.Signaled():
		result.Status = runner.StatusSignalled
		result.ExitStatus = int(wstatus.Signal())
		return &result, nil

	default:
	}

	if uint64(result.Time) > timeLimit*1e9 {
		result.Status = runner.StatusTimeLimitExceeded
	}
	if uint64(result.Memory) > memoryLimit<<20 {
		result.Status = runner.StatusMemoryLimitExceeded
	}

	return &result, nil
}
