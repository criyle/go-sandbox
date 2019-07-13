package forkexec

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
		err1 syscall.Errno
	)

	argv0, argv, envv, err := prepareExec(r.Args, r.Env)
	if err != nil {
		return 0, err
	}

	// prepare work dir
	workdir, err := syscallStringFromString(r.WorkDir)
	if err != nil {
		return 0, err
	}

	// prepare pivot_root param
	pivotRoot, oldRoot, err := preparePivotRoot(r.PivotRoot)
	if err != nil {
		return 0, err
	}

	// prepare mount param
	mountParams, dirsToMake, err := prepareMounts(r.Mounts)
	if err != nil {
		return 0, nil
	}

	// similar to exec_linux, avoid side effect by shuffling around
	fd, nextfd := prepareFds(r.Files)

	// Acquire the fork lock so that no other threads
	// create new fds that are not yet close-on-exec
	// before we fork.
	syscall.ForkLock.Lock()

	// About to call fork.
	// No more allocation or calls of non-assembly functions.
	beforeFork()

	// UnshareFlags (new namespaces) is activated by clone syscall
	pid, _, err1 := syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD)|(r.UnshareFlags&UnshareFlags), 0, 0, 0, 0, 0)
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

	// Get pid of child
	pid, _, err1 = syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
	if err1 != 0 {
		goto childerror
	}

	// Pass 1 & pass 2 assigns fds for child process
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

	// Set the pgid, so that the wait operation can apply to only certain
	// subgroup of processes
	_, _, err1 = syscall.RawSyscall(syscall.SYS_SETPGID, 0, 0, 0)
	if err1 != 0 {
		goto childerror
	}

	// If mount point is unshared, mark root as private to avoid propagate
	// outside to the original mount namespace
	if r.UnshareFlags&syscall.CLONE_NEWNS == syscall.CLONE_NEWNS {
		_, _, err1 = syscall.RawSyscall6(syscall.SYS_MOUNT, uintptr(unsafe.Pointer(&none[0])),
			uintptr(unsafe.Pointer(&slash[0])), 0, syscall.MS_REC|syscall.MS_PRIVATE, 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// chdir to new root before performing mounts
	if pivotRoot != nil {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_CHDIR, uintptr(unsafe.Pointer(pivotRoot)), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// performing mounts
	for i, m := range mountParams {
		// mkdirs(target)
		for _, p := range dirsToMake[i] {
			_, _, err1 = syscall.RawSyscall(syscall.SYS_MKDIR, uintptr(unsafe.Pointer(p)), 0755, 0)
			if err1 != 0 && err1 != syscall.EEXIST {
				goto childerror
			}
		}
		// mount(source, target, fsType, flags, data)
		_, _, err1 = syscall.RawSyscall6(syscall.SYS_MOUNT, uintptr(unsafe.Pointer(m.Source)),
			uintptr(unsafe.Pointer(m.Target)), uintptr(unsafe.Pointer(m.FsType)), uintptr(m.Flags),
			uintptr(unsafe.Pointer(m.Data)), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// pivit_root
	if pivotRoot != nil {
		// mkdir(root/old_root)
		_, _, err1 = syscall.RawSyscall(syscall.SYS_MKDIR, uintptr(unsafe.Pointer(oldRoot)), 0755, 0)
		if err1 != 0 {
			goto childerror
		}

		// pivot_root(root, root/old_root)
		_, _, err1 = syscall.RawSyscall(syscall.SYS_MKDIR, uintptr(unsafe.Pointer(pivotRoot)), uintptr(unsafe.Pointer(oldRoot)), 0)
		if err1 != 0 {
			goto childerror
		}

		// umount(root/old, MNT_DETACH)
		_, _, err1 = syscall.RawSyscall(syscall.SYS_UMOUNT2, uintptr(unsafe.Pointer(oldRoot)), syscall.MNT_DETACH, 0)
		if err1 != 0 {
			goto childerror
		}

		// rmdir(root/old_root)
		_, _, err1 = syscall.RawSyscall(syscall.SYS_RMDIR, uintptr(unsafe.Pointer(oldRoot)), 0755, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// chdir for child
	if workdir != nil {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_CHDIR, uintptr(unsafe.Pointer(workdir)), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Set limit
	for _, rlim := range r.RLimits {
		// Prlimit instead of setrlimit to avoid 32-bit limitation (linux > 3.2)
		_, _, err1 = syscall.RawSyscall6(syscall.SYS_PRLIMIT64, 0, uintptr(rlim.Res), uintptr(unsafe.Pointer(&rlim.Rlim)), 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// No new privs
	if r.NoNewPrivs || r.Seccomp != nil {
		_, _, err1 = syscall.RawSyscall6(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Enable Ptrace
	if r.Ptrace {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_TRACEME), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// if both seccomp and ptrace is defined, then seccomp filter should have
	// traced execve, thus child need parent attached to it first
	if r.StopBeforeSeccomp || (r.Seccomp != nil && r.Ptrace) {
		// Stop to wait for ptrace tracer
		_, _, err1 = syscall.RawSyscall(syscall.SYS_KILL, pid, uintptr(syscall.SIGSTOP), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Load seccomp, stop and wait for tracer
	if r.Seccomp != nil {
		// If execve is seccomp trapped, then tracee stop is necessary
		// otherwise execve will fail due to ENOSYS
		// Do getpid and kill to send SYS_KILL to self
		// need to do before seccomp as these might be traced

		// Load seccomp filter
		_, _, err1 = syscall.RawSyscall(unix.SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(r.Seccomp)))
		if err1 != 0 {
			goto childerror
		}
	}

	// stop before execve syscall
	if r.StopBeforeExec {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_KILL, pid, uintptr(syscall.SIGSTOP), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// at this point, runner is successfully attached for seccomp trap filter
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
