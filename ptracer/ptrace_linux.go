package ptracer

import (
	"syscall"
	"unsafe"
)

// ptrace constants
const (
	NT_PRSTATUS        = 1
	NT_ARM_SYSTEM_CALL = 0x404

	PTRACE_SET_SYSCALL = 23
)

func ptrace(request int, pid int, addr uintptr, data uintptr) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_PTRACE, uintptr(request), uintptr(pid), uintptr(addr), uintptr(data), 0, 0)
	if e1 != 0 {
		err = e1
	}
	return
}

func ptraceGetRegSet(pid int, regs *syscall.PtraceRegs) error {
	iov := getIovec((*byte)(unsafe.Pointer(regs)), int(unsafe.Sizeof(*regs)))
	return ptrace(syscall.PTRACE_GETREGSET, pid, NT_PRSTATUS, uintptr(unsafe.Pointer(&iov)))
}

func ptraceSetRegSet(pid int, regs *syscall.PtraceRegs) error {
	iov := getIovec((*byte)(unsafe.Pointer(regs)), int(unsafe.Sizeof(*regs)))
	return ptrace(syscall.PTRACE_SETREGSET, pid, NT_PRSTATUS, uintptr(unsafe.Pointer(&iov)))
}

func ptraceArm64SetSyscall(pid int, syscallNo int) error {
	iov := getIovec((*byte)(unsafe.Pointer(&syscallNo)), int(unsafe.Sizeof(syscallNo)))
	return ptrace(syscall.PTRACE_SETREGSET, pid, NT_ARM_SYSTEM_CALL, uintptr(unsafe.Pointer(&iov)))
}

func ptraceArmSetSyscall(pid int, syscallNo int) error {
	return ptrace(PTRACE_SET_SYSCALL, pid, 0, uintptr(syscallNo))
}
