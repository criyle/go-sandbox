package main

import (
	"log"
	"os"

	tracer "github.com/criyle/go-judger/tracer"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

func handle(ctx *tracer.Context) tracer.TraceAction {
	syscallNo := ctx.SyscallNo()
	syscallName, err := libseccomp.ScmpSyscall(syscallNo).GetName()
	log.Println("syscall: ", syscallNo, syscallName, err)
	switch syscallName {
	case "open":
		fileptr := ctx.Arg0()
		file := ctx.GetString(fileptr)
		log.Println("open: ", file)
	case "access":
		fileptr := ctx.Arg0()
		file := ctx.GetString(fileptr)
		log.Println("access: ", file)
	case "execve":
		fileptr := ctx.Arg0()
		file := ctx.GetString(fileptr)
		log.Println("execve: ", file)
	}
	return tracer.TraceAllow
}

func main() {
	t := tracer.NewTracer()
	t.Args = os.Args[1:]
	t.TraceHandle = handle
	rt, err := t.StartTrace()
	log.Println(rt, err)
}
