package main

import (
	"fmt"
	"os"
	"syscall"

	tracer "github.com/criyle/go-judger/tracer"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

type handler struct {
	fs          *fileSets
	sc          syscallCounter
	showDetails bool
}

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

func (h *handler) print(v ...interface{}) {
	if h.showDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}

func (h *handler) onDgsFileDetect(ctx *tracer.Context, name string) tracer.TraceAction {
	if h.fs.isSoftBanFile(name) {
		return softBanSyscall(ctx)
	}
	h.print("Dangerous fileopen: (killed)", name)
	return tracer.TraceKill
}

func (h *handler) checkOpen(ctx *tracer.Context, addr uint, flags uint) tracer.TraceAction {
	fn := ctx.GetString(uintptr(addr))
	isReadOnly := (flags&syscall.O_ACCMODE == syscall.O_RDONLY) &&
		(flags&syscall.O_CREAT == 0) &&
		(flags&syscall.O_EXCL == 0) &&
		(flags&syscall.O_TRUNC == 0)

	h.print("open: ", fn, getFileMode(flags))
	if isReadOnly {
		if realPath(fn) != "" && !h.fs.isReadableFile(fn) {
			return h.onDgsFileDetect(ctx, fn)
		}
	} else {
		if realPath(fn) != "" && !h.fs.isWritableFile(fn) {
			return h.onDgsFileDetect(ctx, fn)
		}
	}
	return tracer.TraceAllow
}

func (h *handler) checkRead(ctx *tracer.Context, addr uint) tracer.TraceAction {
	fn := ctx.GetString(uintptr(addr))
	h.print("check read: ", fn)
	if !h.fs.isReadableFile(fn) {
		return h.onDgsFileDetect(ctx, fn)
	}
	return tracer.TraceAllow
}

func (h *handler) checkWrite(ctx *tracer.Context, addr uint) tracer.TraceAction {
	fn := ctx.GetString(uintptr(addr))
	h.print("check write: ", fn)
	if !h.fs.isWritableFile(fn) {
		return h.onDgsFileDetect(ctx, fn)
	}
	return tracer.TraceAllow
}

func (h *handler) checkStat(ctx *tracer.Context, addr uint) tracer.TraceAction {
	fn := ctx.GetString(uintptr(addr))
	h.print("check stat: ", fn)
	if !h.fs.isStatableFile(fn) {
		return h.onDgsFileDetect(ctx, fn)
	}
	return tracer.TraceAllow
}

func (h *handler) Handle(ctx *tracer.Context) tracer.TraceAction {
	syscallNo := ctx.SyscallNo()
	syscallName, err := libseccomp.ScmpSyscall(syscallNo).GetName()
	h.print("syscall: ", syscallNo, syscallName, err)

	switch syscallName {
	case "open":
		return h.checkOpen(ctx, ctx.Arg0(), ctx.Arg1())
	case "openat":
		return h.checkOpen(ctx, ctx.Arg1(), ctx.Arg2())

	case "readlink":
		return h.checkRead(ctx, ctx.Arg0())
	case "readlinkat":
		return h.checkRead(ctx, ctx.Arg1())

	case "unlink":
		return h.checkWrite(ctx, ctx.Arg0())
	case "unlinkat":
		return h.checkWrite(ctx, ctx.Arg1())

	case "access":
		return h.checkStat(ctx, ctx.Arg0())

	case "stat":
		return h.checkStat(ctx, ctx.Arg0())
	case "lstat":
		return h.checkStat(ctx, ctx.Arg0())

	case "execve":
		return h.checkRead(ctx, ctx.Arg0())

	case "chmod":
		return h.checkWrite(ctx, ctx.Arg0())
	case "rename":
		return h.checkWrite(ctx, ctx.Arg0())
	default:
		// if it is traced, then try to count syscall
		if inside, allow := h.sc.check(syscallName); !allow {
			return tracer.TraceKill
		} else if !inside {
			// if it is traced but not counted, it should be soft banned
			return softBanSyscall(ctx)
		}
	}
	return tracer.TraceAllow
}

func (h *handler) GetSyscallName(ctx *tracer.Context) (string, error) {
	syscallNo := ctx.SyscallNo()
	return libseccomp.ScmpSyscall(syscallNo).GetName()
}
