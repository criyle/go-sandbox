// Package vfork provides the mirror of the un-exported syscall.rawVforkSyscall.
// The assembly code is copied from go1.24 syscall package
package vfork

import "syscall"

// RawVforkSyscall provided the mirrored version from un-exported syscall.rawVforkSyscall
// The go:linkname does not work for assembly function and it was suggested by the go team
// to copy over the assembly functions
//
// See go.dev/issue/71892
func RawVforkSyscall(trap, a1, a2, a3 uintptr) (r1 uintptr, err syscall.Errno)
