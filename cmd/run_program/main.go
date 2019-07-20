package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/criyle/go-judger/runconfig"
	"github.com/criyle/go-judger/runprogram"
	"github.com/criyle/go-judger/rununshared"
	"github.com/criyle/go-judger/types/rlimit"
	"github.com/criyle/go-judger/types/specs"
)

const (
	pathEnv = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
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
	var (
		addReadable, addWritable, addRawReadable, addRawWritable       arrayFlags
		allowProc, unsafe, showDetails, namespace                      bool
		pType, result                                                  string
		timeLimit, realTimeLimit, memoryLimit, outputLimit, stackLimit uint64
		inputFileName, outputFileName, errorFileName, workPath         string
		runner                                                         Runner
	)

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
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		printUsage()
	}

	println := func(v ...interface{}) {
		if showDetails {
			fmt.Fprintln(os.Stderr, v...)
		}
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

	addRead := runconfig.GetExtraSet(addReadable, addRawReadable)
	addWrite := runconfig.GetExtraSet(addWritable, addRawWritable)
	h := runconfig.GetConf(pType, workPath, args, addRead, addWrite, allowProc, showDetails)

	// open input / output / err files
	files, err := prepareFiles(inputFileName, outputFileName, errorFileName)
	if err != nil {
		println(err)
		os.Exit(1)
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

	if namespace {
		h.SyscallAllow = append(h.SyscallAllow, h.SyscallTrace...)
		root, err := ioutil.TempDir("", "ns")
		if err != nil {
			panic("cannot make temp root for new namespace")
		}
		runner = &rununshared.RunUnshared{
			Args:    h.Args,
			Env:     []string{pathEnv},
			WorkDir: "/w",
			Files:   fds,
			RLimits: rlims,
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
			ShowDetails: true,
		}
	} else {
		runner = &runprogram.RunProgram{
			Args:    h.Args,
			Env:     []string{pathEnv},
			WorkDir: workPath,
			RLimits: rlims,
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
		}
	}

	var f *os.File
	if result == "stdout" {
		f = os.Stdout
	} else if result == "stderr" {
		f = os.Stderr
	} else {
		f, err := os.OpenFile(result, os.O_WRONLY|os.O_CREATE, 0755)
		if err != nil {
			println("Failed to open result file: ", err)
			os.Exit(1)
		}
		defer f.Close()
	}

	// Run tracer
	rt, err := runner.Start()
	println("results:", rt, err)

	if err != nil {
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
