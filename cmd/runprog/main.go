package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"time"

	"github.com/criyle/go-sandbox/config"
	"github.com/criyle/go-sandbox/container"
	"github.com/criyle/go-sandbox/pkg/cgroup"
	"github.com/criyle/go-sandbox/pkg/memfd"
	"github.com/criyle/go-sandbox/pkg/mount"
	"github.com/criyle/go-sandbox/pkg/rlimit"
	"github.com/criyle/go-sandbox/pkg/seccomp"
	"github.com/criyle/go-sandbox/pkg/seccomp/libseccomp"
	"github.com/criyle/go-sandbox/runner"
	"github.com/criyle/go-sandbox/runner/ptrace"
	"github.com/criyle/go-sandbox/runner/ptrace/filehandler"
	"github.com/criyle/go-sandbox/runner/unshare"
	"github.com/criyle/go-sandbox/types"
)

const (
	pathEnv = "PATH=/usr/local/bin:/usr/bin:/bin"
)

var (
	addReadable, addWritable, addRawReadable, addRawWritable       arrayFlags
	allowProc, unsafe, showDetails, useCGroup, memfile             bool
	timeLimit, realTimeLimit, memoryLimit, outputLimit, stackLimit uint64
	inputFileName, outputFileName, errorFileName, workPath, runt   string

	pType, result string
	args          []string
)

func printUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <args>\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(2)
}

// container init
func init() {
	container.Init()
}

func main() {
	flag.Usage = printUsage
	flag.Uint64Var(&timeLimit, "tl", 1, "Set time limit (in second)")
	flag.Uint64Var(&realTimeLimit, "rtl", 0, "Set real time limit (in second)")
	flag.Uint64Var(&memoryLimit, "ml", 256, "Set memory limit (in mb)")
	flag.Uint64Var(&outputLimit, "ol", 64, "Set output limit (in mb)")
	flag.Uint64Var(&stackLimit, "sl", 1024, "Set stack limit (in mb)")
	flag.StringVar(&inputFileName, "in", "", "Set input file name")
	flag.StringVar(&outputFileName, "out", "", "Set output file name")
	flag.StringVar(&errorFileName, "err", "", "Set error file name")
	flag.StringVar(&workPath, "work-path", "", "Set the work path of the program")
	flag.StringVar(&pType, "type", "default", "Set the program type (for some program such as python)")
	flag.StringVar(&result, "res", "stdout", "Set the file name for output the result")
	flag.Var(&addReadable, "add-readable", "Add a readable file")
	flag.Var(&addWritable, "add-writable", "Add a writable file")
	flag.BoolVar(&unsafe, "unsafe", false, "Don't check dangerous syscalls")
	flag.BoolVar(&showDetails, "show-trace-details", false, "Show trace details")
	flag.BoolVar(&allowProc, "allow-proc", false, "Allow fork, exec... etc.")
	flag.Var(&addRawReadable, "add-readable-raw", "Add a readable file (don't transform to its real path)")
	flag.Var(&addRawWritable, "add-writable-raw", "Add a writable file (don't transform to its real path)")
	flag.BoolVar(&useCGroup, "cgroup", false, "Use cgroup to colloct resource usage")
	flag.BoolVar(&memfile, "memfd", false, "Use memfd as exec file")
	flag.StringVar(&runt, "runner", "ptrace", "Runner for the program (ptrace, ns, container)")
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
	if rt == nil {
		rt = &types.Result{
			Status: types.StatusRunnerError,
		}
	}
	if err == nil && rt.Status != types.StatusNormal {
		err = rt.Status
	}
	debug("setupTime: ", rt.SetUpTime)
	debug("runningTime: ", rt.RunningTime)
	if err != nil {
		debug(err)
		c, ok := err.(types.Status)
		if !ok {
			c = types.StatusRunnerError
		}
		// Handle fatal error from trace
		fmt.Fprintf(f, "%d %d %d %d\n", getStatus(c), int(rt.Time/time.Millisecond), uint64(rt.Memory)>>10, rt.ExitStatus)
		if c == types.StatusRunnerError {
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(f, "%d %d %d %d\n", 0, int(rt.Time/time.Millisecond), uint64(rt.Memory)>>10, rt.ExitStatus)
	}
}

type containerRunner struct {
	container.Environment
	container.ExecveParam
}

func (r *containerRunner) Run(c context.Context) <-chan types.Result {
	return r.Environment.Execve(c, r.ExecveParam)
}

func start() (*types.Result, error) {
	var (
		runner   runner.Runner
		cg       *cgroup.CGroup
		err      error
		execFile uintptr
		rt       types.Result
	)

	addRead := filehandler.GetExtraSet(addReadable, addRawReadable)
	addWrite := filehandler.GetExtraSet(addWritable, addRawWritable)
	args, allow, trace, h := config.GetConf(pType, workPath, args, addRead, addWrite, allowProc)

	if useCGroup {
		b, err := cgroup.NewBuilder("runprog").WithCPUAcct().WithMemory().WithPids().FilterByEnv()
		if err != nil {
			return nil, err
		}
		debug(b)
		cg, err = b.Build()
		if err != nil {
			return nil, err
		}
		defer cg.Destroy()
		if err = cg.SetMemoryLimitInBytes(memoryLimit << 20); err != nil {
			return nil, err
		}
	}

	syncFunc := func(pid int) error {
		if cg != nil {
			if err := cg.AddProc(pid); err != nil {
				return err
			}
		}
		return nil
	}

	if memfile {
		fin, err := os.Open(args[0])
		if err != nil {
			return nil, fmt.Errorf("filed to open args[0]: %v", err)
		}
		execf, err := memfd.DupToMemfd("run_program", fin)
		if err != nil {
			return nil, fmt.Errorf("dup to memfd failed: %v", err)
		}
		fin.Close()
		defer execf.Close()
		execFile = execf.Fd()
		debug("memfd: ", execFile)
	}

	// open input / output / err files
	files, err := prepareFiles(inputFileName, outputFileName, errorFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare files: %v", err)
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
		CPU:      timeLimit,
		CPUHard:  realTimeLimit,
		FileSize: outputLimit << 20,
		Stack:    stackLimit << 20,
	}
	debug("rlimit: ", rlims)
	debug("defaultMount: ", mount.DefaultMounts)

	actionDefault := seccomp.ActionKill
	if showDetails {
		actionDefault = seccomp.ActionTrace.WithReturnCode(seccomp.MsgDisallow)
	}

	limit := types.Limit{
		TimeLimit:   time.Duration(timeLimit) * time.Second,
		MemoryLimit: types.Size(memoryLimit << 20),
	}

	if runt == "container" {
		root, err := ioutil.TempDir("", "dm")
		if err != nil {
			return nil, fmt.Errorf("cannot make temp root for container namespace: %v", err)
		}
		defer os.RemoveAll(root)

		b := container.Builder{
			Root: root,
		}

		m, err := b.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to new container: %v", err)
		}
		defer m.Destroy()
		err = m.Ping()
		if err != nil {
			return nil, fmt.Errorf("failed to ping container: %v", err)
		}
		runner = &containerRunner{
			Environment: m,
			ExecveParam: container.ExecveParam{
				Args:     args,
				Env:      []string{pathEnv},
				Fds:      fds,
				ExecFile: execFile,
				RLimits:  rlims.PrepareRLimit(),
				SyncFunc: syncFunc,
			},
		}
	} else if runt == "ns" {
		builder := libseccomp.Builder{
			Allow:   append(allow, trace...),
			Default: actionDefault,
		}
		filter, err := builder.Build()
		if err != nil {
			return nil, fmt.Errorf("cannot build seccomp filter %v", err)
		}
		root, err := ioutil.TempDir("", "ns")
		if err != nil {
			return nil, fmt.Errorf("cannot make temp root for new namespace")
		}
		defer os.RemoveAll(root)
		mounts, err := mount.NewBuilder().WithMounts(mount.DefaultMounts).WithBind(root, "w", true).Build(true)
		if err != nil {
			return nil, fmt.Errorf("cannot make rootfs mounts")
		}
		runner = &unshare.Runner{
			Args:        args,
			Env:         []string{pathEnv},
			ExecFile:    execFile,
			WorkDir:     "/w",
			Files:       fds,
			RLimits:     rlims.PrepareRLimit(),
			Limit:       limit,
			Seccomp:     filter,
			Root:        root,
			Mounts:      mounts,
			ShowDetails: showDetails,
			SyncFunc:    syncFunc,
			HostName:    "run_program",
			DomainName:  "run_program",
		}
	} else if runt == "ptrace" {
		builder := libseccomp.Builder{
			Allow:   allow,
			Trace:   trace,
			Default: actionDefault,
		}
		filter, err := builder.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to create seccomp filter %v", err)
		}
		runner = &ptrace.Runner{
			Args:        args,
			Env:         []string{pathEnv},
			ExecFile:    execFile,
			WorkDir:     workPath,
			RLimits:     rlims.PrepareRLimit(),
			Limit:       limit,
			Files:       fds,
			Seccomp:     filter,
			ShowDetails: showDetails,
			Unsafe:      unsafe,
			Handler:     h,
			SyncFunc:    syncFunc,
		}
	} else {
		return nil, fmt.Errorf("invalid runner type: %s", runt)
	}

	// gracefully shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	// Run tracer
	sTime := time.Now()
	c, cancel := context.WithTimeout(context.Background(), time.Duration(int64(realTimeLimit)*int64(time.Second)))
	defer cancel()

	s := runner.Run(c)
	rTime := time.Now()

	select {
	case <-sig:
		cancel()
		rt = <-s
		rt.Status = types.StatusRunnerError

	case rt = <-s:
	}
	eTime := time.Now()

	if rt.SetUpTime == 0 {
		rt.SetUpTime = rTime.Sub(sTime)
		rt.RunningTime = eTime.Sub(rTime)
	}

	debug("results:", rt, err)

	if useCGroup {
		cpu, err := cg.CpuacctUsage()
		if err != nil {
			return nil, fmt.Errorf("cgroup cpu: %v", err)
		}
		memory, err := cg.MemoryMaxUsageInBytes()
		if err != nil {
			return nil, fmt.Errorf("cgroup memory: %v", err)
		}
		debug("cgroup: cpu: ", cpu, " memory: ", memory)
		rt.Time = time.Duration(cpu)
		rt.Memory = types.Size(memory)
		debug("cgroup:", rt)
	}
	return &rt, nil
}

func debug(v ...interface{}) {
	if showDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}

// Status defines uoj/run_program constants
type Status int

// UOJ run_program constants
const (
	StatusNormal  Status = iota // 0
	StatusInvalid               // 1
	StatusRE                    // 2
	StatusMLE                   // 3
	StatusTLE                   // 4
	StatusOLE                   // 5
	StatusBan                   // 6
	StatusFatal                 // 7
)

func getStatus(s types.Status) int {
	switch s {
	case types.StatusNormal:
		return int(StatusNormal)
	case types.StatusInvalid:
		return int(StatusInvalid)
	case types.StatusTimeLimitExceeded:
		return int(StatusTLE)
	case types.StatusMemoryLimitExceeded:
		return int(StatusMLE)
	case types.StatusOutputLimitExceeded:
		return int(StatusOLE)
	case types.StatusDisallowedSyscall:
		return int(StatusBan)
	case types.StatusSignalled, types.StatusNonzeroExitStatus:
		return int(StatusRE)
	default:
		return int(StatusFatal)
	}
}
