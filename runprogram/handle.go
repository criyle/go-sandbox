package runprogram

import (
	"fmt"
	"os"
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"

	"github.com/criyle/go-judger/tracer"
)

type tracerHandler struct {
	ShowDetails, Unsafe bool
	Handler             Handler
}

func (h *tracerHandler) Debug(v ...interface{}) {
	if h.ShowDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}

func (h *tracerHandler) checkOpen(ctx *tracer.Context, addr uint, flags uint) TraceAction {
	fn := ctx.GetString(uintptr(addr))
	isReadOnly := (flags&syscall.O_ACCMODE == syscall.O_RDONLY) &&
		(flags&syscall.O_CREAT == 0) &&
		(flags&syscall.O_EXCL == 0) &&
		(flags&syscall.O_TRUNC == 0)

	h.Debug("open: ", fn, getFileMode(flags))
	if isReadOnly {
		return h.Handler.CheckRead(fn)
	}
	return h.Handler.CheckWrite(fn)
}

func (h *tracerHandler) checkRead(ctx *tracer.Context, addr uint) TraceAction {
	fn := ctx.GetString(uintptr(addr))
	h.Debug("check read: ", fn)
	return h.Handler.CheckRead(fn)
}

func (h *tracerHandler) checkWrite(ctx *tracer.Context, addr uint) TraceAction {
	fn := ctx.GetString(uintptr(addr))
	h.Debug("check write: ", fn)
	return h.Handler.CheckWrite(fn)
}

func (h *tracerHandler) checkStat(ctx *tracer.Context, addr uint) TraceAction {
	fn := ctx.GetString(uintptr(addr))
	h.Debug("check stat: ", fn)
	return h.Handler.CheckStat(fn)
}

func (h *tracerHandler) Handle(ctx *tracer.Context) tracer.TraceAction {
	var (
		action           TraceAction
		syscallNo        = ctx.SyscallNo()
		syscallName, err = libseccomp.ScmpSyscall(syscallNo).GetName()
	)
	h.Debug("syscall: ", syscallNo, syscallName, err)

	switch syscallName {
	case "open":
		action = h.checkOpen(ctx, ctx.Arg0(), ctx.Arg1())
	case "openat":
		action = h.checkOpen(ctx, ctx.Arg1(), ctx.Arg2())

	case "readlink":
		action = h.checkRead(ctx, ctx.Arg0())
	case "readlinkat":
		action = h.checkRead(ctx, ctx.Arg1())

	case "unlink":
		action = h.checkWrite(ctx, ctx.Arg0())
	case "unlinkat":
		action = h.checkWrite(ctx, ctx.Arg1())

	case "access":
		action = h.checkStat(ctx, ctx.Arg0())
	case "faccessat":
		action = h.checkStat(ctx, ctx.Arg1())

	case "stat", "stat64":
		action = h.checkStat(ctx, ctx.Arg0())
	case "lstat", "lstat64":
		action = h.checkStat(ctx, ctx.Arg0())

	case "execve":
		action = h.checkRead(ctx, ctx.Arg0())

	case "chmod":
		action = h.checkWrite(ctx, ctx.Arg0())
	case "rename":
		action = h.checkWrite(ctx, ctx.Arg0())
	default:
		action = h.Handler.CheckSyscall(syscallName)
	}

	switch action {
	case TraceAllow:
		return tracer.TraceAllow
	case TraceBan:
		h.Debug("<soft ban syscall>")
		return softBanSyscall(ctx)
	default:
		return tracer.TraceKill
	}
}

func (h *tracerHandler) GetSyscallName(ctx *tracer.Context) (string, error) {
	syscallNo := ctx.SyscallNo()
	return libseccomp.ScmpSyscall(syscallNo).GetName()
}

func (h *tracerHandler) HandlerDisallow(name string) error {
	if !h.Unsafe {
		return tracer.TraceCodeBan
	}
	return nil
}

func softBanSyscall(ctx *tracer.Context) tracer.TraceAction {
	ctx.SetReturnValue(-int(BanRet))
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
