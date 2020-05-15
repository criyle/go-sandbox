package forkexec

import (
	"syscall"
	_ "unsafe" // use go:linkname

	"github.com/criyle/go-sandbox/pkg/darwin" // use sandbox_init
)

var _ = darwin.SandboxInit

//go:linkname funcPC syscall.funcPC
func funcPC(f func()) uintptr

//go:linkname syscall3 syscall.syscall
func syscall3(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname rawSyscall syscall.rawSyscall
func rawSyscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname rawSyscall6 syscall.rawSyscall6
func rawSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname libc_fork_trampoline syscall.libc_fork_trampoline
func libc_fork_trampoline()

//go:linkname libc_close_trampoline syscall.libc_close_trampoline
func libc_close_trampoline()

//go:linkname libc_read_trampoline syscall.libc_read_trampoline
func libc_read_trampoline()

//go:linkname libc_write_trampoline syscall.libc_write_trampoline
func libc_write_trampoline()

//go:linkname libc_fcntl_trampoline syscall.libc_fcntl_trampoline
func libc_fcntl_trampoline()

//go:linkname libc_dup2_trampoline syscall.libc_dup2_trampoline
func libc_dup2_trampoline()

//go:linkname libc_chdir_trampoline syscall.libc_chdir_trampoline
func libc_chdir_trampoline()

//go:linkname libc_setrlimit_trampoline syscall.libc_setrlimit_trampoline
func libc_setrlimit_trampoline()

//go:linkname libc_execve_trampoline syscall.libc_execve_trampoline
func libc_execve_trampoline()

//go:linkname libc_exit_trampoline syscall.libc_exit_trampoline
func libc_exit_trampoline()

//go:linkname libc_sandbox_init_trampoline github.com/criyle/go-sandbox/pkg/darwin.libc_sandbox_init_trampoline
func libc_sandbox_init_trampoline()

//go:linkname libc_sandbox_free_error_trampoline github.com/criyle/go-sandbox/pkg/darwin.libc_sandbox_free_error_trampoline
func libc_sandbox_free_error_trampoline()

//go:linkname fcntl syscall.fcntl
func fcntl(fd int, cmd int, arg int) (val int, err error)
