package seccomp

import (
	"syscall"
)

// SockFprog converts Filter to SockFprog for seccomp syscall
func (f Filter) SockFprog() *syscall.SockFprog {
	b := []syscall.SockFilter(f)
	return &syscall.SockFprog{
		Len:    uint16(len(b)),
		Filter: &b[0],
	}
}
