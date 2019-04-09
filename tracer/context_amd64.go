package tracer

import "syscall"

// SyscallNo get current syscall no
func (c *Context) SyscallNo() int {
	return int(c.regs.Orig_rax)
}

// Arg0 gets the arg0 for the current syscall
func (c *Context) Arg0() uint64 {
	return c.regs.Rdi
}

// Arg1 gets the arg1 for the current syscall
func (c *Context) Arg1() uint64 {
	return c.regs.Rsi
}

// Arg2 gets the arg2 for the current syscall
func (c *Context) Arg2() uint64 {
	return c.regs.Rdx
}

// Arg3 gets the arg3 for the current syscall
func (c *Context) Arg3() uint64 {
	return c.regs.R10
}

// Arg4 gets the arg4 for the current syscall
func (c *Context) Arg4() uint64 {
	return c.regs.R8
}

// Arg5 gets the arg5 for the current syscall
func (c *Context) Arg5() uint64 {
	return c.regs.R9
}

// GetString get the string from process data segment
func (c *Context) GetString(addr uint64) string {
	buff := make([]byte, syscall.PathMax)
	syscall.PtracePeekData(c.Pid, uintptr(addr), buff)
	return string(buff[:clen(buff)])
}

// SetReturnValue set the return value if skip the syscall
func (c *Context) SetReturnValue(retval int) {
	c.regs.Rax = uint64(retval)
}

func (c *Context) skipSyscall() error {
	c.regs.Orig_rax = uint64(1<<64 - 1) //-1
	return syscall.PtraceSetRegs(c.Pid, &c.regs)
}
