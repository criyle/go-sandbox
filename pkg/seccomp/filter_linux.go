// Package seccomp provides a generated filter format for seccomp filter
package seccomp

import "syscall"

// Filter is the BPF seccomp filter value
type Filter []syscall.SockFilter

// SockFprog converts Filter to SockFprog for the seccomp syscall.
// It returns nil when the filter is empty.
func (f Filter) SockFprog() *syscall.SockFprog {
	if len(f) == 0 {
		return nil
	}
	return &syscall.SockFprog{
		Len:    uint16(len(f)),
		Filter: &f[0],
	}
}
