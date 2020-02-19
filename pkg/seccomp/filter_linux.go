package seccomp

import (
	"syscall"
	"unsafe"
)

// SockFprog converts Filter to SockFprog for seccomp syscall
func (f Filter) SockFprog() *syscall.SockFprog {
	b := []byte(f)
	return &syscall.SockFprog{
		Len:    uint16(len(b) / 8),
		Filter: (*syscall.SockFilter)(unsafe.Pointer(&b[0])),
	}
}
