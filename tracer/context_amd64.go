package tracer

import (
	"syscall"

	unix "golang.org/x/sys/unix"
)

// SyscallNo get current syscall no
func (c *Context) SyscallNo() uint {
	return uint(c.regs.Orig_rax)
}

// Arg0 gets the arg0 for the current syscall
func (c *Context) Arg0() uint {
	return uint(c.regs.Rdi)
}

// Arg1 gets the arg1 for the current syscall
func (c *Context) Arg1() uint {
	return uint(c.regs.Rsi)
}

// Arg2 gets the arg2 for the current syscall
func (c *Context) Arg2() uint {
	return uint(c.regs.Rdx)
}

// Arg3 gets the arg3 for the current syscall
func (c *Context) Arg3() uint {
	return uint(c.regs.R10)
}

// Arg4 gets the arg4 for the current syscall
func (c *Context) Arg4() uint {
	return uint(c.regs.R8)
}

// Arg5 gets the arg5 for the current syscall
func (c *Context) Arg5() uint {
	return uint(c.regs.R9)
}

// SetReturnValue set the return value if skip the syscall
func (c *Context) SetReturnValue(retval int) {
	c.regs.Rax = uint64(retval)
}

func (c *Context) skipSyscall() error {
	c.regs.Orig_rax = ^uint64(0) //-1
	return syscall.PtraceSetRegs(c.Pid, &c.regs)
}

func getIovecs(base *byte, l int) []unix.Iovec {
	return []unix.Iovec{
		unix.Iovec{
			Base: base,
			Len:  uint64(l),
		},
	}
}
