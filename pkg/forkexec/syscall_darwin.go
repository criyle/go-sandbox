package forkexec

import (
	"syscall"
	_ "unsafe" // use go:linkname
)

//go:linkname syscall3 syscall.syscall
func syscall3(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname rawSyscall syscall.rawSyscall
func rawSyscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname rawSyscall6 syscall.rawSyscall6
func rawSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

var libc_fork_trampoline_addr uintptr

var libc_close_trampoline_addr uintptr

var libc_read_trampoline_addr uintptr

var libc_write_trampoline_addr uintptr

var libc_fcntl_trampoline_addr uintptr

var libc_dup2_trampoline_addr uintptr

var libc_chdir_trampoline_addr uintptr

var libc_setrlimit_trampoline_addr uintptr

var libc_execve_trampoline_addr uintptr

var libc_exit_trampoline_addr uintptr

var libc_setpgid_trampoline_addr uintptr

//go:linkname fcntl syscall.fcntl
func fcntl(fd int, cmd int, arg int) (val int, err error)
