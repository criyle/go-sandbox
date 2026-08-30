package ptracer

import (
	"os"
	"sync"
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
	// UseVMReadv determines whether to use process_vm_readv to read strings.
	// It starts enabled and is disabled when that fast path is unavailable.
	UseVMReadv    = true
	pageSize      = 4 << 10
	vmReadvMu     sync.Mutex
	stringBufPool = sync.Pool{New: func() any {
		return make([]byte, syscall.PathMax)
	}}
)

func init() {
	pageSize = os.Getpagesize()
}

func getTrapContext(pid int) (*Context, error) {
	var regs syscall.PtraceRegs
	//err := syscall.PtraceGetRegs(pid, &regs)
	err := ptraceGetRegSet(pid, &regs)
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
	buff := stringBufPool.Get().([]byte)
	defer stringBufPool.Put(buff)
	vmReadvMu.Lock()
	useVMReadv := UseVMReadv
	vmReadvMu.Unlock()
	if useVMReadv {
		if err := vmReadStr(c.Pid, addr, buff); err != nil {
			// Disable the fast path when it is unavailable or forbidden. An
			// invalid tracee address is not global evidence that it is unusable.
			if no, ok := err.(syscall.Errno); ok {
				if no == syscall.ENOSYS || no == syscall.EPERM || no == syscall.EACCES {
					vmReadvMu.Lock()
					UseVMReadv = false
					vmReadvMu.Unlock()
				}
			}
		} else {
			return string(buff[:clen(buff)])
		}
	}
	if _, err := syscall.PtracePeekData(c.Pid, addr, buff); err != nil {
		return ""
	}
	return string(buff[:clen(buff)])
}
