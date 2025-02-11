package ptracer

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
	return syscall.Syscall6(unix.SYS_PROCESS_VM_READV, uintptr(pid),
		uintptr(unsafe.Pointer(&localIov[0])), uintptr(len(localIov)),
		uintptr(unsafe.Pointer(&remoteIov[0])), uintptr(len(remoteIov)),
		flags)
}

func vmRead(pid int, addr uintptr, buff []byte) (int, error) {
	l := len(buff)
	localIov := getIovecs(&buff[0], l)
	remoteIov := getIovecs((*byte)(unsafe.Pointer(addr)), l)
	n, _, err := processVMReadv(pid, localIov, remoteIov, uintptr(0))
	if err == 0 {
		return int(n), nil
	}
	return int(n), err
}

func getIovecs(base *byte, l int) []unix.Iovec {
	return []unix.Iovec{getIovec(base, l)}
}

func vmReadStr(pid int, addr uintptr, buff []byte) error {
	// Handle unaligned address: calculate remaining bytes to page boundary
	totalRead := 0 // Total bytes read so far
	// Calculate distance to next page boundary, nextRead is the number of bytes to read
	nextRead := pageSize - int(addr%uintptr(pageSize))
	if nextRead == 0 {
		nextRead = pageSize // If exactly at page boundary, use full page size
	}

	// Read in a loop until buffer is full or termination condition is met
	for len(buff) > 0 {
		// If remaining buffer is smaller than planned read size, reduce read size
		if restToRead := len(buff); restToRead < nextRead {
			nextRead = restToRead
		}

		// Read data from current position
		curRead, err := vmRead(pid, addr+uintptr(totalRead), buff[:nextRead])
		if err != nil {
			return err // Read error
		}
		if curRead == 0 {
			break // No more data to read
		}
		if hasNull(buff[:curRead]) {
			break // Found string terminator
		}

		// Update counters and buffer
		totalRead += curRead  // Update total bytes read
		buff = buff[curRead:] // Move buffer pointer
		nextRead = pageSize   // Reset to full page size
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
