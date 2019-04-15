package main

import (
	"fmt"
	"os"
	"syscall"

	tracer "github.com/criyle/go-judger/tracer"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

func softBanSyscall(ctx *tracer.Context) tracer.TraceAction {
	ctx.SetReturnValue(-int(syscall.EACCES))
	return tracer.TraceBan
}

func getFileMode(flags uint) string {
	switch flags & syscall.O_ACCMODE {
	case syscall.O_RDONLY:
		return "r "
	case syscall.O_WRONLY:
		return "w "
	case syscall.O_RDWR:
		return "wr"
	default:
		return "??"
	}
}

func getHandle(t *tracer.Tracer, pType string, addRead []string, addWrite []string, allowProc bool) func(ctx *tracer.Context) tracer.TraceAction {
	var (
		fs          = newFileSets()
		sc          = newSyscallCounter()
		showDetails = t.ShowDetails
	)

	inifConf(t, &fs, &sc, pType, addRead, addWrite, allowProc)

	print := func(v ...interface{}) {
		if showDetails {
			fmt.Fprintln(os.Stderr, v...)
		}
	}

	onDgsFileDetect := func(ctx *tracer.Context, name string) tracer.TraceAction {
		if fs.isSoftBanFile(name) {
			return softBanSyscall(ctx)
		}
		print("Dangerous fileopen: (killed)", name)
		return tracer.TraceKill
	}

	checkOpen := func(ctx *tracer.Context, addr uint, flags uint) tracer.TraceAction {
		fn := ctx.GetString(uintptr(addr))
		isReadOnly := (flags&syscall.O_ACCMODE == syscall.O_RDONLY) &&
			(flags&syscall.O_CREAT == 0) &&
			(flags&syscall.O_EXCL == 0) &&
			(flags&syscall.O_TRUNC == 0)

		print("open: ", fn, getFileMode(flags))
		if isReadOnly {
			if realPath(fn) != "" && !fs.isReadableFile(fn) {
				return onDgsFileDetect(ctx, fn)
			}
		} else {
			if realPath(fn) != "" && !fs.isWritableFile(fn) {
				return onDgsFileDetect(ctx, fn)
			}
		}
		return tracer.TraceAllow
	}

	checkRead := func(ctx *tracer.Context, addr uint) tracer.TraceAction {
		fn := ctx.GetString(uintptr(addr))
		print("check read: ", fn)
		if !fs.isReadableFile(fn) {
			return onDgsFileDetect(ctx, fn)
		}
		return tracer.TraceAllow
	}

	checkWrite := func(ctx *tracer.Context, addr uint) tracer.TraceAction {
		fn := ctx.GetString(uintptr(addr))
		print("check write: ", fn)
		if !fs.isWritableFile(fn) {
			return onDgsFileDetect(ctx, fn)
		}
		return tracer.TraceAllow
	}

	checkStat := func(ctx *tracer.Context, addr uint) tracer.TraceAction {
		fn := ctx.GetString(uintptr(addr))
		print("check stat: ", fn)
		if !fs.isStatableFile(fn) {
			return onDgsFileDetect(ctx, fn)
		}
		return tracer.TraceAllow
	}

	return func(ctx *tracer.Context) tracer.TraceAction {
		syscallNo := ctx.SyscallNo()
		syscallName, err := libseccomp.ScmpSyscall(syscallNo).GetName()
		print("syscall: ", syscallNo, syscallName, err)

		switch syscallName {
		case "open":
			return checkOpen(ctx, ctx.Arg0(), ctx.Arg1())
		case "openat":
			return checkOpen(ctx, ctx.Arg1(), ctx.Arg2())

		case "readlink":
			return checkRead(ctx, ctx.Arg0())
		case "readlinkat":
			return checkRead(ctx, ctx.Arg1())

		case "unlink":
			return checkWrite(ctx, ctx.Arg0())
		case "unlinkat":
			return checkWrite(ctx, ctx.Arg1())

		case "access":
			return checkStat(ctx, ctx.Arg0())

		case "stat":
			return checkStat(ctx, ctx.Arg0())
		case "lstat":
			return checkStat(ctx, ctx.Arg0())

		case "execve":
			return checkRead(ctx, ctx.Arg0())

		case "chmod":
			return checkWrite(ctx, ctx.Arg0())
		case "rename":
			return checkWrite(ctx, ctx.Arg0())
		default:
			// if it is traced, then try to count syscall
			if inside, allow := sc.check(syscallName); !allow {
				return tracer.TraceKill
			} else if !inside {
				// if it is traced but not counted, it should be soft banned
				return softBanSyscall(ctx)
			}
		}
		return tracer.TraceAllow
	}
}
