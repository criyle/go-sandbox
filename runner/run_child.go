package main

import (
	"os"
	"syscall"
	"unsafe" // required for go:linkname.

	"golang.org/x/sys/unix"
)

//go:linkname beforeFork syscall.runtime_BeforeFork
func beforeFork()

//go:linkname afterFork syscall.runtime_AfterFork
func afterFork()

//go:linkname afterForkInChild syscall.runtime_AfterForkInChild
func afterForkInChild()

type rlimit struct {
	resource int
	rlim     syscall.Rlimit
}

// StartChild will fork, load seccomp and execv and being traced by ptrace
// Reference to src/syscall/exec_linux.go
// The runtime OS thread must be locked before calling this function
//go:noinline
//go:norace
func (r *ProgramRunner) StartChild() (int, error) {
	var (
		err1 syscall.Errno
		bpf  *syscall.SockFprog
	)
	// verify
	r.verify()

	// make exec args
	argv0, err := syscall.BytePtrFromString(r.Args[0])
	if err != nil {
		return 0, err
	}
	argv, err := syscall.SlicePtrFromStrings(r.Args)
	if err != nil {
		return 0, err
	}
	// make env
	envv, err := syscall.SlicePtrFromStrings(r.Env)
	if err != nil {
		return 0, err
	}

	// make bpf using libseccomp
	if r.Filter != nil {
		bpf, err = FilterToBPF(r.Filter)
		if err != nil {
			return 0, err
		}
	}

	rlimits := []rlimit{
		// CPU limit
		{
			resource: syscall.RLIMIT_CPU,
			rlim: syscall.Rlimit{
				Cur: r.TimeLimit,
				Max: r.RealTimeLimit,
			},
		},
		// File limit
		{
			resource: syscall.RLIMIT_FSIZE,
			rlim: syscall.Rlimit{
				Cur: r.OutputLimit << 20,
				Max: r.OutputLimit << 20,
			},
		},
		// Stack limit
		{
			resource: syscall.RLIMIT_STACK,
			rlim: syscall.Rlimit{
				Cur: r.StackLimit << 20,
				Max: r.StackLimit << 20,
			},
		},
	}

	// work dir
	var dir *byte
	if r.WorkPath != "" {
		dir, err = syscall.BytePtrFromString(r.WorkPath)
		if err != nil {
			return 0, err
		}
	}

	// stdin, stdout, stderr
	files := make([]*os.File, 3)
	if r.InputFileName != "" {
		files[0], err = os.OpenFile(r.InputFileName, os.O_RDONLY, 0755)
		if err != nil {
			return 0, err
		}
		defer files[0].Close()
	}
	if r.OutputFileName != "" {
		files[1], err = os.OpenFile(r.OutputFileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0755)
		if err != nil {
			return 0, err
		}
		defer files[1].Close()
	}
	if r.ErrorFileName != "" {
		files[2], err = os.OpenFile(r.ErrorFileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0755)
		if err != nil {
			return 0, err
		}
		defer files[2].Close()
	}
	fds := make([]uintptr, 3)
	for i, f := range files {
		if f != nil {
			fds[i] = f.Fd()
		}
	}

	// Acquire the fork lock so that no other threads
	// create new fds that are not yet close-on-exec
	// before we fork.
	syscall.ForkLock.Lock()

	// About to call fork.
	// No more allocation or calls of non-assembly functions.
	beforeFork()

	pid, _, err1 := syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
	if err1 != 0 || pid != 0 {
		// restore all signals
		afterFork()
		syscall.ForkLock.Unlock()

		if err1 != 0 {
			return int(pid), syscall.Errno(err1)
		}
		return int(pid), nil
	}

	// In child process
	afterForkInChild()
	// Notice: cannot call any functions beyond this point

	// Set limit
	for _, rlim := range rlimits {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_SETRLIMIT, uintptr(rlim.resource), uintptr(unsafe.Pointer(&rlim.rlim)), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Chdir
	if dir != nil {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_CHDIR, uintptr(unsafe.Pointer(dir)), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// stdin, stdout, stderr
	// the other file already marked as close on exec
	for i, fd := range fds {
		if fd != 0 {
			_, _, err1 = syscall.RawSyscall(syscall.SYS_DUP, fd, uintptr(i), 0)
			if err1 != 0 {
				goto childerror
			}
		}
	}

	// Enable ptrace
	_, _, err1 = syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_TRACEME), 0, 0)
	if err1 != 0 {
		goto childerror
	}

	if r.Filter != nil {
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

	if r.Filter != nil {
		// set seccomp
		//_, _, err1 = syscall.Syscall6(syscall.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&bpf[0])), 0, 0, 0)
		// SECCOMP_SET_MODE_FILTER = 1
		// SECCOMP_FILTER_FLAG_TSYNC = 1
		_, _, err1 = syscall.Syscall(unix.SYS_SECCOMP, 1, 1, uintptr(unsafe.Pointer(bpf)))
		if err1 != 0 {
			goto childerror
		}
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
