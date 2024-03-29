package forkexec

import (
	"syscall"
	"unsafe"
)

// Reference to src/syscall/exec_darwin.go
//go:norace
func forkAndExecInChild(r *Runner, argv0 *byte, argv, env []*byte, workdir, profile *byte, p [2]int) (r1 uintptr, err1 syscall.Errno) {
	var (
		err2   syscall.Errno
		errBuf *byte
	)

	// similar to exec_linux, avoid side effect by shuffling around
	fd, nextfd := prepareFds(r.Files)
	pipe := p[1]

	// About to call fork.
	// No more allocation or calls of non-assembly functions.
	beforeFork()

	// UnshareFlags (new namespaces) is activated by clone syscall
	r1, _, err1 = rawSyscall(libc_fork_trampoline_addr, 0, 0, 0)
	if err1 != 0 || r1 != 0 {
		// in parent process, immediate return
		return
	}

	// In child process
	afterForkInChild()
	// Notice: cannot call any GO functions beyond this point

	// Close write end of pipe
	if _, _, err1 = rawSyscall(libc_close_trampoline_addr, uintptr(p[0]), 0, 0); err1 != 0 {
		goto childerror
	}

	// Set pg id
	_, _, err1 = rawSyscall(libc_setpgid_trampoline_addr, 0, 0, 0)
	if err1 != 0 {
		goto childerror
	}

	// Pass 1 & pass 2 assigns fds for child process
	// Pass 1: fd[i] < i => nextfd
	if pipe < nextfd {
		_, _, err1 = rawSyscall(libc_dup2_trampoline_addr, uintptr(pipe), uintptr(nextfd), 0)
		if err1 != 0 {
			goto childerror
		}
		rawSyscall(libc_fcntl_trampoline_addr, uintptr(nextfd), syscall.F_SETFD, syscall.FD_CLOEXEC)
		pipe = nextfd
		nextfd++
	}
	for i := 0; i < len(fd); i++ {
		if fd[i] >= 0 && fd[i] < int(i) {
			// Avoid fd rewrite
			if nextfd == pipe {
				nextfd++
			}
			_, _, err1 = rawSyscall(libc_dup2_trampoline_addr, uintptr(fd[i]), uintptr(nextfd), 0)
			if err1 != 0 {
				goto childerror
			}
			rawSyscall(libc_fcntl_trampoline_addr, uintptr(nextfd), syscall.F_SETFD, syscall.FD_CLOEXEC)
			// Set up close on exec
			fd[i] = nextfd
			nextfd++
		}
	}
	// Pass 2: fd[i] => i
	for i := 0; i < len(fd); i++ {
		if fd[i] == -1 {
			rawSyscall(libc_close_trampoline_addr, uintptr(i), 0, 0)
			continue
		}
		if fd[i] == int(i) {
			// dup2(i, i) will not clear close on exec flag, need to reset the flag
			_, _, err1 = rawSyscall(libc_fcntl_trampoline_addr, uintptr(fd[i]), syscall.F_SETFD, 0)
			if err1 != 0 {
				goto childerror
			}
			continue
		}
		_, _, err1 = rawSyscall(libc_dup2_trampoline_addr, uintptr(fd[i]), uintptr(i), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// chdir for child
	if workdir != nil {
		_, _, err1 = rawSyscall(libc_chdir_trampoline_addr, uintptr(unsafe.Pointer(workdir)), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Set limit
	for _, rlim := range r.RLimits {
		_, _, err1 = rawSyscall(libc_setrlimit_trampoline_addr, uintptr(rlim.Res), uintptr(unsafe.Pointer(&rlim.Rlim)), 0)
		if err1 != 0 {
			if err1 == syscall.EINVAL && (rlim.Res == syscall.RLIMIT_DATA || rlim.Res == syscall.RLIMIT_AS) {
				continue
			}
			goto childerror
		}
	}

	// Load sandbox profile
	if profile != nil {
		r1, _, err1 = rawSyscall(libc_sandbox_init_trampoline_addr, uintptr(unsafe.Pointer(profile)), 0, uintptr(unsafe.Pointer(&errBuf)))
		if err1 != 0 {
			goto childerror
		}
		if r1 != 0 {
			err1 = 253
			goto childerror
		}
		rawSyscall(libc_sandbox_free_error_trampoline_addr, uintptr(unsafe.Pointer(errBuf)), 0, 0)
	}

	// Sync before exec
	err2 = 0
	r1, _, err1 = rawSyscall(libc_write_trampoline_addr, uintptr(pipe), uintptr(unsafe.Pointer(&err2)), unsafe.Sizeof(err2))
	if r1 == 0 || err1 != 0 {
		goto childerror
	}

	r1, _, err1 = rawSyscall(libc_read_trampoline_addr, uintptr(pipe), uintptr(unsafe.Pointer(&err2)), unsafe.Sizeof(err2))
	if r1 == 0 || err1 != 0 {
		goto childerror
	}

	// Time to exec.
	_, _, err1 = rawSyscall(libc_execve_trampoline_addr,
		uintptr(unsafe.Pointer(argv0)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&env[0])))

childerror:
	// send error code on pipe
	rawSyscall(libc_write_trampoline_addr, uintptr(pipe), uintptr(unsafe.Pointer(&err1)), unsafe.Sizeof(err1))
	for {
		rawSyscall(libc_exit_trampoline_addr, uintptr(err1+err2), 0, 0)
	}
}
