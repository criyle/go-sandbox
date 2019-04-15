package main

import (
	"flag"
	"fmt"
	"os"

	tracer "github.com/criyle/go-judger/tracer"
)

// TODO: syscall handle, file access checker
func main() {
	var (
		addReadable, addWritable       arrayFlags
		addRawReadable, addRawWritable arrayFlags
		addRead, addWrite              []string
		allowProc                      bool
		pType, result                  string
	)

	t := tracer.NewTracer()
	flag.Uint64Var(&t.TimeLimit, "tl", 1, "Set time limit (in second)")
	flag.Uint64Var(&t.RealTimeLimit, "rtl", 1, "Set real time limit (in second)")
	flag.Uint64Var(&t.MemoryLimit, "ml", 256, "Set memory limit (in mb)")
	flag.Uint64Var(&t.OutputLimit, "ol", 64, "Set output limit (in mb)")
	flag.Uint64Var(&t.StackLimit, "sl", 1024, "Set stack limit (in mb)")
	flag.StringVar(&t.InputFileName, "in", "", "Set input file name")
	flag.StringVar(&t.OutputFileName, "out", "", "Set output file name")
	flag.StringVar(&t.ErrorFileName, "err", "", "Set error file name")
	flag.StringVar(&t.WorkPath, "work-path", "", "Set the work path of the program")
	flag.StringVar(&pType, "type", "default", "Set the program type (for some program such as python)")
	flag.StringVar(&result, "res", "stdout", "Set the file name for output the result")
	flag.Var(&addReadable, "add-readable", "Add a readable file")
	flag.Var(&addWritable, "add-writable", "Add a writable file")
	flag.BoolVar(&t.Unsafe, "unsafe", false, "Don't check dangerous syscalls")
	flag.BoolVar(&t.ShowDetails, "show-trace-details", false, "Show trace details")
	flag.BoolVar(&allowProc, "allow-proc", false, "Allow fork, exec... etc.")
	flag.Var(&addRawReadable, "add-readable-raw", "Add a readable file (don't transform to its real path)")
	flag.Var(&addRawWritable, "add-writable-raw", "Add a writable file (don't transform to its real path)")

	flag.Parse()

	t.Args = flag.Args()

	for _, name := range addReadable {
		addRead = append(addRead, realPath(name))
	}

	for _, name := range addRawReadable {
		addRead = append(addRead, name)
	}

	for _, name := range addWritable {
		addWrite = append(addWrite, realPath(name))
	}

	for _, name := range addRawWritable {
		addWrite = append(addWrite, name)
	}

	handle := getHandle(&t, pType, addRead, addWrite, allowProc)
	t.TraceHandle = handle

	var f *os.File
	if result == "stdout" {
		f = os.Stdout
	} else if result == "stderr" {
		f = os.Stderr
	} else {
		f, err := os.OpenFile(result, os.O_WRONLY|os.O_CREATE, 0755)
		if err != nil {
			fmt.Println("Failed to open result file: ", err)
			os.Exit(1)
		}
		defer f.Close()
	}

	rt, err := t.StartTrace()
	if t.ShowDetails {
		fmt.Fprintln(os.Stderr, "Used process_vm_readv: ", tracer.UseVMReadv)
	}

	if err != nil {
		c, ok := err.(tracer.TraceCode)
		if !ok {
			c = tracer.TraceCodeFatal
		}
		// Handle fatal error from trace
		if rt != nil {
			fmt.Fprintf(f, "%d %d %d %d\n", int(c), rt.UserTime, rt.UserMem, rt.ExitCode)
		}
		if c == tracer.TraceCodeFatal {
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(f, "%d %d %d %d\n", 0, rt.UserTime, rt.UserMem, rt.ExitCode)
	}
}
