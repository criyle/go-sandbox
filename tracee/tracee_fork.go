package tracee

import (
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

// Start will fork, load seccomp and execv and being traced by ptrace
// Return pid and potential error
// Reference to src/syscall/exec_linux.go
// The runtime OS thread must be locked before calling this function
//go:noinline
//go:norace
func (r *Runner) Start() (int, error) {
	var (
		err1    syscall.Errno
		workdir *byte
		nextfd  int
	)

	// make exec args0
	argv0, err := syscall.BytePtrFromString(r.Args[0])
	if err != nil {
		return 0, err
	}
	// make exec args
	argv, err := syscall.SlicePtrFromStrings(r.Args)
	if err != nil {
		return 0, err
	}
	// make env
	envv, err := syscall.SlicePtrFromStrings(r.Env)
	if err != nil {
		return 0, err
	}

	// make work dir
	if r.WorkDir != "" {
		workdir, err = syscall.BytePtrFromString(r.WorkDir)
		if err != nil {
			return 0, err
		}
	}

	// similar to exec_linux, avoid side effect by shuffling around
	fd := make([]int, len(r.Files))
	nextfd = len(r.Files)
	for i, ufd := range r.Files {
		if nextfd < int(ufd) {
			nextfd = int(ufd)
		}
		fd[i] = int(ufd)
	}
	nextfd++

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
	// Notice: cannot call any GO functions beyond this point

	// Set the pgid, so that the wait operation can apply to only certain
	// subgroup of processes
	_, _, err1 = syscall.RawSyscall(syscall.SYS_SETPGID, 0, 0, 0)
	if err1 != 0 {
		goto childerror
	}

	// Set limit
	for _, rlim := range r.RLimits {
		// Prlimit instead of setrlimit to avoid 32-bit limitation (linux > 3.2)
		_, _, err1 = syscall.RawSyscall6(syscall.SYS_PRLIMIT64, 0, uintptr(rlim.Res), uintptr(unsafe.Pointer(&rlim.Rlim)), 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Chdir if needed
	if workdir != nil {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_CHDIR, uintptr(unsafe.Pointer(workdir)), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Pass 1: fd[i] < i => nextfd
	for i := 0; i < len(fd); i++ {
		if fd[i] >= 0 && fd[i] < int(i) {
			_, _, err1 = syscall.RawSyscall(syscall.SYS_DUP3, uintptr(fd[i]), uintptr(nextfd), 0)
			if err1 != 0 {
				goto childerror
			}
			// Set up close on exec
			syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(nextfd), syscall.F_SETFD, syscall.FD_CLOEXEC)
			fd[i] = nextfd
			nextfd++
		}
	}

	// Pass 2: fd[i] => i
	for i := 0; i < len(fd); i++ {
		if fd[i] == -1 {
			syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(i), 0, 0)
			continue
		}
		if fd[i] == int(i) {
			// dup2(i, i) will not clear close on exec flag, need to reset the flag
			_, _, err1 = syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fd[i]), syscall.F_SETFD, 0)
			if err1 != 0 {
				goto childerror
			}
			continue
		}
		_, _, err1 = syscall.RawSyscall(syscall.SYS_DUP3, uintptr(fd[i]), uintptr(i), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Enable Ptrace
	_, _, err1 = syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_TRACEME), 0, 0)
	if err1 != 0 {
		goto childerror
	}

	// Load seccomp, stop and wait for tracer
	if r.BPF != nil {
		// Check if support
		// SECCOMP_SET_MODE_STRICT = 0, args = 1 for invalid operation
		_, _, err1 = syscall.RawSyscall(unix.SYS_SECCOMP, 0, 1, 0)
		if err1 != syscall.EINVAL {
			goto childerror
		}

		// Load the filter manually
		// No new privs
		_, _, err1 = syscall.RawSyscall6(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}

		// If execve is seccomp trapped, then tracee stop is necessary
		// otherwise execve will fail due to ENOSYS
		// Do getpid and kill to send SYS_KILL to self
		// need to do before seccomp as these might be traced
		// Get pid of child
		pid, _, err1 = syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}

		// Stop to wait for tracer
		_, _, err1 = syscall.RawSyscall(syscall.SYS_KILL, pid, uintptr(syscall.SIGSTOP), 0)
		if err1 != 0 {
			goto childerror
		}

		// Load seccomp filter
		// SECCOMP_SET_MODE_FILTER = 1
		// SECCOMP_FILTER_FLAG_TSYNC = 1
		_, _, err1 = syscall.RawSyscall(unix.SYS_SECCOMP, 1, 1, uintptr(unsafe.Pointer(r.BPF)))
		if err1 != 0 {
			goto childerror
		}
	}

	// at this point, tracer is successfully attached for seccomp trap filter
	// or execve traped without seccomp filter
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
