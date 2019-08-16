package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/criyle/go-judger/cgroup"
	"github.com/criyle/go-judger/deamon"
	"github.com/criyle/go-judger/memfd"
	"github.com/criyle/go-judger/runconfig"
	"github.com/criyle/go-judger/runprogram"
	"github.com/criyle/go-judger/rununshared"
	"github.com/criyle/go-judger/types/rlimit"
	"github.com/criyle/go-judger/types/specs"
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

// Runner can be ptraced runner or namespaced runner
type Runner interface {
	Start() (specs.TraceResult, error)
}

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
	rt, f, err := run()

	if err != nil {
		debug(err)
		c, ok := err.(specs.TraceCode)
		if !ok {
			c = specs.TraceCodeFatal
		}
		// Handle fatal error from trace
		fmt.Fprintf(f, "%d %d %d %d\n", int(c), rt.UserTime, rt.UserMem, rt.ExitCode)
		if c == specs.TraceCodeFatal {
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(f, "%d %d %d %d\n", 0, rt.UserTime, rt.UserMem, rt.ExitCode)
	}
}

func run() (*specs.TraceResult, *os.File, error) {
	var (
		runner   Runner
		cg       *cgroup.CGroup
		err      error
		execFile uintptr
		rt       specs.TraceResult
		f        *os.File
	)

	addRead := runconfig.GetExtraSet(addReadable, addRawReadable)
	addWrite := runconfig.GetExtraSet(addWritable, addRawWritable)
	h := runconfig.GetConf(pType, workPath, args, addRead, addWrite, allowProc, showDetails)

	if useCGroup {
		cg, err = cgroup.NewCGroup("run_program")
		if err != nil {
			return nil, nil, err
		}
		defer cg.Destroy()
		if err = cg.SetMemoryLimitInBytes(memoryLimit << 20); err != nil {
			return nil, nil, err
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
			return nil, nil, fmt.Errorf("filed to open args[0]: %v", err)
		}
		execf, err := memfd.DupToMemfd("run_program", fin)
		if err != nil {
			return nil, nil, fmt.Errorf("dup to memfd failed: %v", err)
		}
		fin.Close()
		defer execf.Close()
		execFile = execf.Fd()
		debug("memfd: ", execFile)
	}

	// open input / output / err files
	files, err := prepareFiles(inputFileName, outputFileName, errorFileName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare files: %v", err)
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
		sTime := time.Now()
		root, err := ioutil.TempDir("", "dm")
		if err != nil {
			return nil, nil, fmt.Errorf("cannot make temp root for deamon namespace: %v", err)
		}
		defer os.RemoveAll(root)

		m, err := deamon.New(root)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to new master: %v", err)
		}
		err = m.Ping()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to ping deamon: %v", err)
		}

		rTime := time.Now()
		done := make(chan struct{})
		s, err := m.Execve(done, &deamon.ExecveParam{
			Args:     args,
			Envv:     []string{pathEnv},
			Fds:      fds,
			ExecFile: execFile,
			RLimits:  rlims.PrepareRLimit(),
			SyncFunc: syncFunc,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to execve: %v", err)
		}
		tC := time.After(time.Duration(int64(realTimeLimit) * int64(time.Second)))
		select {
		case <-tC:
			close(done)
			rt = <-s

		case rt = <-s:
		}
		eTime := time.Now()
		rt.SetUpTime = int64(rTime.Sub(sTime))
		rt.RunningTime = int64(eTime.Sub(rTime))
		m.Destroy()
	} else if namespace {
		h.SyscallAllow = append(h.SyscallAllow, h.SyscallTrace...)
		root, err := ioutil.TempDir("", "ns")
		if err != nil {
			return nil, nil, fmt.Errorf("cannot make temp root for new namespace")
		}
		defer os.RemoveAll(root)

		runner = &rununshared.RunUnshared{
			Args:     h.Args,
			Env:      []string{pathEnv},
			ExecFile: execFile,
			WorkDir:  "/w",
			Files:    fds,
			RLimits:  rlims,
			ResLimits: specs.ResLimit{
				TimeLimit:     timeLimit * 1e3,
				RealTimeLimit: realTimeLimit * 1e3,
				MemoryLimit:   memoryLimit << 10,
			},
			SyscallAllowed: h.SyscallAllow,
			Root:           root,
			Mounts: rununshared.GetDefaultMounts(root, []rununshared.AddBind{
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
		runner = &runprogram.RunProgram{
			Args:     h.Args,
			Env:      []string{pathEnv},
			ExecFile: execFile,
			WorkDir:  workPath,
			RLimits:  rlims,
			TraceLimit: specs.ResLimit{
				TimeLimit:     timeLimit * 1e3,
				RealTimeLimit: realTimeLimit * 1e3,
				MemoryLimit:   memoryLimit << 10,
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

	if result == "stdout" {
		f = os.Stdout
	} else if result == "stderr" {
		f = os.Stderr
	} else {
		f, err := os.Create(result)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to open result file: %v", err)
		}
		defer f.Close()
	}

	// Run tracer
	if runner != nil {
		rt, err = runner.Start()
	}
	debug("results:", rt, err)

	if useCGroup {
		cpu, err := cg.CpuacctUsage()
		if err != nil {
			return nil, nil, fmt.Errorf("cgroup cpu: %v", err)
		}
		memory, err := cg.MemoryMaxUsageInBytes()
		if err != nil {
			return nil, nil, fmt.Errorf("cgroup memory: %v", err)
		}
		debug("cgroup: cpu: ", cpu, " memory: ", memory)
		rt.UserTime = cpu / uint64(time.Millisecond)
		rt.UserMem = memory >> 10
	}
	return &rt, f, nil
}

func debug(v ...interface{}) {
	if showDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}
