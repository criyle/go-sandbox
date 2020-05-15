// Package seccomp provides a generated filter format for seccomp filter
package seccomp

import "syscall"

// Filter is the BPF seccomp filter value
type Filter []syscall.SockFilter
