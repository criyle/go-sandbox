package main

import (
	"syscall"
	"unsafe" // required for go:linkname.

	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

//go:linkname beforeFork syscall.runtime_BeforeFork
func beforeFork()

//go:linkname afterFork syscall.runtime_AfterFork
func afterFork()

//go:linkname afterForkInChild syscall.runtime_AfterForkInChild
func afterForkInChild()

// ForkAndLoadSeccomp will fork, load seccomp and execv and being traced by ptrace
// Reference to src/syscall/exec_linux.go
// The runtime OS thread must be locked before calling this function
//go:noinline
//go:norace
func ForkAndLoadSeccomp(args []string, filter *libseccomp.ScmpFilter) (int, error) {
	var (
		err1 syscall.Errno
	)
	// make exec args
	argv0, err := syscall.BytePtrFromString(args[0])
	if err != nil {
		return 0, err
	}
	argv, err := syscall.SlicePtrFromStrings(args)
	if err != nil {
		return 0, err
	}
	envv, err := syscall.SlicePtrFromStrings([]string{""})
	if err != nil {
		return 0, err
	}

	// make bpf using libseccomp
	bpf, err := FilterToBPF(filter)
	if err != nil {
		return 0, err
	}

	// About to call fork.
	// No more allocation or calls of non-assembly functions.
	beforeFork()

	pid, _, err1 := syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
	if err1 != 0 || pid != 0 {
		// restore all signals
		afterFork()
		if err1 != 0 {
			return int(pid), syscall.Errno(err1)
		}
		return int(pid), nil
	}

	// In child process
	afterForkInChild()
	// Notice: cannot call any functions beyond this point

	// Enable ptrace
	_, _, err1 = syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_TRACEME), 0, 0)
	if err1 != 0 {
		goto childerror
	}

	// Check if support
	// SECCOMP_SET_MODE_STRICT = 0, args = 1 for invalid operation
	_, _, err1 = syscall.Syscall(unix.SYS_SECCOMP, 0, 1, 0)
	if err1 != syscall.EINVAL {
		goto childerror
	}

	// Load the filter manually
	// No new priv
	_, _, err1 = syscall.Syscall6(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0)
	if err1 != 0 {
		goto childerror
	}

	// Get pid of child
	pid, _, err1 = syscall.Syscall(syscall.SYS_GETPID, 0, 0, 0)
	if err1 != 0 {
		goto childerror
	}

	// Stop to wait for tracer
	_, _, err1 = syscall.Syscall(syscall.SYS_KILL, pid, uintptr(syscall.SIGSTOP), 0)
	if err1 != 0 {
		goto childerror
	}

	// set seccomp
	//_, _, err1 = syscall.Syscall6(syscall.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&bpf[0])), 0, 0, 0)
	// SECCOMP_SET_MODE_FILTER = 1
	// SECCOMP_FILTER_FLAG_TSYNC = 1
	_, _, err1 = syscall.Syscall(unix.SYS_SECCOMP, 1, 1, uintptr(unsafe.Pointer(bpf)))
	if err1 != 0 {
		goto childerror
	}

	// time to exec
	_, _, err1 = syscall.RawSyscall(syscall.SYS_EXECVE,
		uintptr(unsafe.Pointer(argv0)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envv[0])))

childerror:
	syscall.RawSyscall(syscall.SYS_EXIT, uintptr(err1), 0, 0)
	// cannot reach this point
	panic("cannot reach")
}
