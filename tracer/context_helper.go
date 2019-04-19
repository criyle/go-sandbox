package tracer

import (
	"syscall"
	"unsafe"

	unix "golang.org/x/sys/unix"
)

// TODO: make this method not to call ptrace too much
func ptraceReadStr(pid int, addr uintptr, buff []byte) {
	syscall.PtracePeekData(pid, addr, buff)
}

func processVMReadv(pid int, localIov, remoteIov []unix.Iovec,
	flags uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.RawSyscall6(unix.SYS_PROCESS_VM_READV, uintptr(pid),
		uintptr(unsafe.Pointer(&localIov[0])), uintptr(len(localIov)),
		uintptr(unsafe.Pointer(&remoteIov[0])), uintptr(len(remoteIov)),
		flags)
}

func vmRead(pid int, addr uintptr, buff []byte) (int, error) {
	l := len(buff)
	localIov := getIovecs(&buff[0], l)
	remoteIov := getIovecs((*byte)(unsafe.Pointer(addr)), l)
	n, _, err := processVMReadv(pid, localIov, remoteIov, uintptr(0))
	return int(n), err
}

func vmReadStr(pid int, addr uintptr, buff []byte) error {
	// Deal with unaligned addr
	n := 0
	r := pageSize - int(addr%uintptr(pageSize))
	if r == 0 {
		r = pageSize
	}

	for len(buff) > 0 {
		if l := len(buff); r < l {
			r = l
		}

		nn, err := vmRead(pid, addr+uintptr(n), buff[:r])
		if err != nil {
			return err
		}

		if hasNull(buff[:nn]) {
			return nil
		}

		n += nn
		buff = buff[nn:]
		r = pageSize
	}
	return nil
}

func hasNull(buff []byte) bool {
	for _, b := range buff {
		if b == 0 {
			return true
		}
	}
	return false
}

func clen(b []byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			return i
		}
	}
	return len(b) + 1
}
