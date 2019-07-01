package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/criyle/go-judger/runconfig"
	"github.com/criyle/go-judger/runprogram"
	"github.com/criyle/go-judger/tracer"
)

func printUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <args>\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	var (
		addReadable, addWritable, addRawReadable, addRawWritable       arrayFlags
		allowProc, unsafe, showDetails                                 bool
		pType, result                                                  string
		timeLimit, realTimeLimit, memoryLimit, outputLimit, stackLimit uint
		inputFileName, outputFileName, errorFileName, workPath         string
	)

	flag.Usage = printUsage
	flag.UintVar(&timeLimit, "tl", 1, "Set time limit (in second)")
	flag.UintVar(&realTimeLimit, "rtl", 0, "Set real time limit (in second)")
	flag.UintVar(&memoryLimit, "ml", 256, "Set memory limit (in mb)")
	flag.UintVar(&outputLimit, "ol", 64, "Set output limit (in mb)")
	flag.UintVar(&stackLimit, "sl", 1024, "Set stack limit (in mb)")
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

	runner := &runprogram.RunProgram{
		Args:    h.Args,
		Env:     []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		WorkDir: workPath,
		RLimits: runprogram.RLimits{
			CPU:      timeLimit,
			CPUHard:  realTimeLimit,
			FileSize: outputLimit,
			Stack:    stackLimit,
		},
		TraceLimit: runprogram.TraceLimit{
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
	println("used process_vm_readv: ", tracer.UseVMReadv)

	if err != nil {
		c, ok := err.(tracer.TraceCode)
		if !ok {
			c = tracer.TraceCodeFatal
		}
		// Handle fatal error from trace
		fmt.Fprintf(f, "%d %d %d %d\n", int(c), rt.UserTime, rt.UserMem, rt.ExitCode)
		if c == tracer.TraceCodeFatal {
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(f, "%d %d %d %d\n", 0, rt.UserTime, rt.UserMem, rt.ExitCode)
	}
}
