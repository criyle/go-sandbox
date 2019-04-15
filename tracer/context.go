package tracer

import (
	"os"
	"syscall"
)

// Context is the context for current syscall trap
// used to retrive syscall number and arguments
type Context struct {
	// Pid is current context process pid
	Pid int
	// current reg context (platform dependent)
	regs syscall.PtraceRegs
}

var (
	// UseVMReadv determine whether use ProcessVMReadv syscall to read str
	// initial true and becomes false if tried and failed with ENOSYS
	UseVMReadv = true
	pageSize   = 4 << 10
)

func init() {
	pageSize = os.Getpagesize()
}

func getTrapContext(pid int) (*Context, error) {
	var regs syscall.PtraceRegs
	err := syscall.PtraceGetRegs(pid, &regs)
	if err != nil {
		return nil, err
	}
	return &Context{
		Pid:  pid,
		regs: regs,
	}, nil
}

// GetString get the string from process data segment
func (c *Context) GetString(addr uintptr) string {
	buff := make([]byte, syscall.PathMax)
	if UseVMReadv {
		if err := vmReadStr(c.Pid, addr, buff); err != nil {
			// if ENOSYS, then disable this function
			if no, ok := err.(syscall.Errno); ok {
				if no == syscall.ENOSYS {
					UseVMReadv = false
				}
			}
		} else {
			return string(buff[:clen(buff)])
		}
	}
	syscall.PtracePeekData(c.Pid, addr, buff)
	return string(buff[:clen(buff)])
}
