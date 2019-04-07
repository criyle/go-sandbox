package tracer

import "syscall"

// Context is the context for current syscall trap
// used to retrive syscall number and arguments
type Context struct {
	// Pid is current context process pid
	Pid int
	// current reg context (platform dependent)
	regs syscall.PtraceRegs
}

func clen(b []byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			return i
		}
	}
	return len(b) + 1
}

func getTrapContext(pid int) (*Context, error) {
	var regs syscall.PtraceRegs
	err := syscall.PtraceGetRegs(pid, &regs)
	if err != nil {
		return nil, err
	}
	return &Context{
		pid:  pid,
		regs: regs,
	}, nil
}
