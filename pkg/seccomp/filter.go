// Package seccomp provides a generated filter format for seccomp filter

// +build linux

package seccomp

import (
	"syscall"
	"unsafe"
)

// Filter is the BPF seccomp filter value
type Filter []byte

// SockFprog converts Filter to SockFprog for seccomp syscall
func (f Filter) SockFprog() *syscall.SockFprog {
	b := []byte(f)
	return &syscall.SockFprog{
		Len:    uint16(len(b) / 8),
		Filter: (*syscall.SockFilter)(unsafe.Pointer(&b[0])),
	}
}
