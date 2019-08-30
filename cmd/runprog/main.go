package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"time"

	"github.com/criyle/go-sandbox/deamon"
	"github.com/criyle/go-sandbox/pkg/cgroup"
	"github.com/criyle/go-sandbox/pkg/memfd"
	"github.com/criyle/go-sandbox/pkg/rlimit"
	"github.com/criyle/go-sandbox/runner"
	"github.com/criyle/go-sandbox/runner/config"
	"github.com/criyle/go-sandbox/runner/ptrace"
	"github.com/criyle/go-sandbox/runner/unshare"
	"github.com/criyle/go-sandbox/types"
)

const (
	pathEnv = "PATH=/usr/local/bin:/usr/bin:/bin"
)

var (
	addReadable, addWritable, addRawReadable, addRawWritable       arrayFlags
	allowProc, unsafe, showDetails, namespace, useCGroup, memfile  bool
	timeLimit, realTimeLimit, memoryLimit, outputLimit, stackLimit uint64
	inputFileName, outputFileName, errorFileName, workPath         string

	useDeamon     bool
	pType, result string
	args          []string
)

func printUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <args>\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	deamon.ContainerInit()

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
	flag.BoolVar(&namespace, "ns", false, "Use namespace to restrict file accesses")
	flag.BoolVar(&useCGroup, "cgroup", false, "Use cgroup to colloct resource usage")
	flag.BoolVar(&memfile, "memfd", false, "Use memfd as exec file")
	flag.BoolVar(&useDeamon, "deamon", false, "Use deamon container to execute file")
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
			Status: types.StatusFatal,
		}
	}
	if err == nil && rt.Status != types.StatusNormal {
		err = rt.Status
	}
	if err != nil {
		debug(err)
		c, ok := err.(types.Status)
		if !ok {
			c = types.StatusFatal
		}
		// Handle fatal error from trace
		fmt.Fprintf(f, "%d %d %d %d\n", int(c), rt.UserTime, rt.UserMem, rt.ExitStatus)
		if c == types.StatusFatal {
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(f, "%d %d %d %d\n", 0, rt.UserTime, rt.UserMem, rt.ExitStatus)
	}
}

type deamonRunner struct {
	*deamon.Master
	*deamon.ExecveParam
}

func (r *deamonRunner) Start(done <-chan struct{}) (<-chan types.Result, error) {
	return r.Master.Execve(done, r.ExecveParam)
}

func start() (*types.Result, error) {
	var (
		runner   runner.Runner
		cg       *cgroup.CGroup
		err      error
		execFile uintptr
		rt       types.Result
	)

	addRead := config.GetExtraSet(addReadable, addRawReadable)
	addWrite := config.GetExtraSet(addWritable, addRawWritable)
	h := config.GetConf(pType, workPath, args, addRead, addWrite, allowProc, showDetails)

	if useCGroup {
		cg, err = cgroup.NewCGroup("run_program")
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
		FileSize: outputLimit,
		Stack:    stackLimit,
	}

	if useDeamon {
		root, err := ioutil.TempDir("", "dm")
		if err != nil {
			return nil, fmt.Errorf("cannot make temp root for deamon namespace: %v", err)
		}
		defer os.RemoveAll(root)

		m, err := deamon.New(root)
		if err != nil {
			return nil, fmt.Errorf("failed to new master: %v", err)
		}
		defer m.Destroy()
		err = m.Ping()
		if err != nil {
			return nil, fmt.Errorf("failed to ping deamon: %v", err)
		}
		runner = &deamonRunner{
			Master: m,
			ExecveParam: &deamon.ExecveParam{
				Args:     args,
				Envv:     []string{pathEnv},
				Fds:      fds,
				ExecFile: execFile,
				RLimits:  rlims.PrepareRLimit(),
				SyncFunc: syncFunc,
			},
		}
	} else if namespace {
		h.SyscallAllow = append(h.SyscallAllow, h.SyscallTrace...)
		root, err := ioutil.TempDir("", "ns")
		if err != nil {
			return nil, fmt.Errorf("cannot make temp root for new namespace")
		}
		defer os.RemoveAll(root)

		runner = &unshare.Runner{
			Args:     h.Args,
			Env:      []string{pathEnv},
			ExecFile: execFile,
			WorkDir:  "/w",
			Files:    fds,
			RLimits:  rlims,
			ResLimits: types.Limit{
				TimeLimit:   timeLimit * 1e3,
				MemoryLimit: memoryLimit << 10,
			},
			SyscallAllowed: h.SyscallAllow,
			Root:           root,
			Mounts: unshare.GetDefaultMounts(root, []unshare.AddBind{
				{
					Source: workPath,
					Target: "w",
				},
			}),
			ShowDetails: showDetails,
			SyncFunc:    syncFunc,
			HostName:    "run_program",
			DomainName:  "run_program",
		}
	} else {
		runner = &ptrace.Runner{
			Args:     h.Args,
			Env:      []string{pathEnv},
			ExecFile: execFile,
			WorkDir:  workPath,
			RLimits:  rlims,
			TraceLimit: types.Limit{
				TimeLimit:   timeLimit * 1e3,
				MemoryLimit: memoryLimit << 10,
			},
			Files:          fds,
			SyscallAllowed: h.SyscallAllow,
			SyscallTraced:  h.SyscallTrace,
			ShowDetails:    showDetails,
			Unsafe:         unsafe,
			Handler:        h,
			SyncFunc:       syncFunc,
		}
	}

	// gracefully shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	// Run tracer
	sTime := time.Now()
	done := make(chan struct{})
	s, err := runner.Start(done)
	rTime := time.Now()
	if err != nil {
		return nil, fmt.Errorf("failed to execve: %v", err)
	}
	tC := time.After(time.Duration(int64(realTimeLimit) * int64(time.Second)))
	select {
	case <-sig:
		close(done)
		rt = <-s
		rt.Status = types.StatusFatal

	case <-tC:
		close(done)
		rt = <-s

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
		rt.UserTime = cpu / uint64(time.Millisecond)
		rt.UserMem = memory >> 10
	}
	return &rt, nil
}

func debug(v ...interface{}) {
	if showDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}
