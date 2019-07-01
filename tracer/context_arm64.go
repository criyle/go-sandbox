package tracer

import (
	unix "golang.org/x/sys/unix"
)

// SyscallNo get current syscall no
func (c *Context) SyscallNo() uint {
	return uint(c.regs.Regs[8]) // R8
}

// Arg0 gets the arg0 for the current syscall
func (c *Context) Arg0() uint {
	return uint(c.regs.Regs[0]) //R0
}

// Arg1 gets the arg1 for the current syscall
func (c *Context) Arg1() uint {
	return uint(c.regs.Regs[1]) // R1
}

// Arg2 gets the arg2 for the current syscall
func (c *Context) Arg2() uint {
	return uint(c.regs.Regs[2]) // R2
}

// Arg3 gets the arg3 for the current syscall
func (c *Context) Arg3() uint {
	return uint(c.regs.Regs[3]) // R3
}

// Arg4 gets the arg4 for the current syscall
func (c *Context) Arg4() uint {
	return uint(c.regs.Regs[4]) // R4
}

// Arg5 gets the arg5 for the current syscall
func (c *Context) Arg5() uint {
	return uint(c.regs.Regs[5]) //R5
}

// SetReturnValue set the return value if skip the syscall
func (c *Context) SetReturnValue(retval int) {
	c.regs.Regs[0] = uint64(retval) // R0
}

func (c *Context) skipSyscall() error {
	err := ptraceSetRegSet(c.Pid, &c.regs)
	if err != nil {
		return err
	}
	return ptraceArm64SetSyscall(c.Pid, -1)
}

func getIovec(base *byte, l int) unix.Iovec {
	return unix.Iovec{
		Base: base,
		Len:  uint64(l),
	}
}
