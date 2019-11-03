package forkexec

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Reference to src/syscall/exec_linux.go
//go:norace
func forkAndExecInChild(r *Runner, argv0 *byte, argv, env []*byte, workdir, hostname, domainname, pivotRoot *byte, p [2]int) (r1 uintptr, err1 syscall.Errno) {
	var (
		pid         uintptr
		err2        syscall.Errno
		unshareUser = r.CloneFlags&unix.CLONE_NEWUSER == unix.CLONE_NEWUSER
	)

	// similar to exec_linux, avoid side effect by shuffling around
	fd, nextfd := prepareFds(r.Files)
	pipe := p[1]

	// Acquire the fork lock so that no other threads
	// create new fds that are not yet close-on-exec
	// before we fork.
	syscall.ForkLock.Lock()

	// About to call fork.
	// No more allocation or calls of non-assembly functions.
	beforeFork()

	// UnshareFlags (new namespaces) is activated by clone syscall
	r1, _, err1 = syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD)|(r.CloneFlags&UnshareFlags), 0, 0, 0, 0, 0)
	if err1 != 0 || r1 != 0 {
		// in parent process, immediate return
		return
	}

	// In child process
	afterForkInChild()
	// Notice: cannot call any GO functions beyond this point

	// Close write end of pipe
	if _, _, err1 = syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(p[0]), 0, 0); err1 != 0 {
		goto childerror
	}

	// If usernamespace is unshared, uid map and gid map is required to create folders
	// and files
	// We need parent to setup uid_map / gid_map for us since we do not have capabilities
	// in the original namespace
	// At the same time, socket pair / pipe synchronization is required as well
	if unshareUser {
		r1, _, err1 = syscall.RawSyscall(syscall.SYS_READ, uintptr(pipe), uintptr(unsafe.Pointer(&err2)), unsafe.Sizeof(err2))
		if err1 != 0 {
			goto childerror
		}
		if r1 != unsafe.Sizeof(err2) {
			err1 = syscall.EINVAL
			goto childerror
		}
		if err2 != 0 {
			err1 = err2
			goto childerror
		}
	}

	// Get pid of child
	pid, _, err1 = syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
	if err1 != 0 {
		goto childerror
	}

	// set the credential for the child process(exec_linux.go)
	if cred := r.Credential; cred != nil {
		ngroups := uintptr(len(cred.Groups))
		groups := uintptr(0)
		if ngroups > 0 {
			groups = uintptr(unsafe.Pointer(&cred.Groups[0]))
		}
		if !(r.GIDMappings != nil && !r.GIDMappingsEnableSetgroups && ngroups == 0) && !cred.NoSetGroups {
			_, _, err1 = syscall.RawSyscall(unix.SYS_SETGROUPS, ngroups, groups, 0)
			if err1 != 0 {
				goto childerror
			}
		}
		_, _, err1 = syscall.RawSyscall(unix.SYS_SETGID, uintptr(cred.Gid), 0, 0)
		if err1 != 0 {
			goto childerror
		}
		_, _, err1 = syscall.RawSyscall(unix.SYS_SETUID, uintptr(cred.Uid), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Pass 1 & pass 2 assigns fds for child process
	// Pass 1: fd[i] < i => nextfd
	if pipe < nextfd {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_DUP3, uintptr(pipe), uintptr(nextfd), syscall.O_CLOEXEC)
		if err1 != 0 {
			goto childerror
		}
		pipe = nextfd
		nextfd++
	}
	if r.ExecFile > 0 && int(r.ExecFile) < nextfd {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_DUP3, r.ExecFile, uintptr(nextfd), syscall.O_CLOEXEC)
		if err1 != 0 {
			goto childerror
		}
		r.ExecFile = uintptr(nextfd)
		nextfd++
	}
	for i := 0; i < len(fd); i++ {
		// Avoid fd rewrite
		for nextfd == i || (r.ExecFile > 0 && nextfd == int(r.ExecFile)) {
			nextfd++
		}
		if fd[i] >= 0 && fd[i] < int(i) {
			_, _, err1 = syscall.RawSyscall(syscall.SYS_DUP3, uintptr(fd[i]), uintptr(nextfd), syscall.O_CLOEXEC)
			if err1 != 0 {
				goto childerror
			}
			// Set up close on exec
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
	if r.CloneFlags&syscall.CLONE_NEWNS == syscall.CLONE_NEWNS {
		_, _, err1 = syscall.RawSyscall6(syscall.SYS_MOUNT, uintptr(unsafe.Pointer(&none[0])),
			uintptr(unsafe.Pointer(&slash[0])), 0, syscall.MS_REC|syscall.MS_PRIVATE, 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// mount tmpfs & chdir to new root before performing mounts
	if pivotRoot != nil {
		// mount("tmpfs", root, "tmpfs", 0, "")
		_, _, err1 = syscall.RawSyscall6(syscall.SYS_MOUNT, uintptr(unsafe.Pointer(&tmpfs[0])),
			uintptr(unsafe.Pointer(pivotRoot)), uintptr(unsafe.Pointer(&tmpfs[0])), 0,
			uintptr(unsafe.Pointer(&empty[0])), 0)
		if err1 != 0 {
			goto childerror
		}

		_, _, err1 = syscall.RawSyscall(syscall.SYS_CHDIR, uintptr(unsafe.Pointer(pivotRoot)), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// performing mounts
	for _, m := range r.Mounts {
		// mkdirs(target)
		for i, p := range m.Prefixes {
			// if target mount point is a file, mknod(target)
			if i == len(m.Prefixes)-1 && m.MakeNod {
				_, _, err1 = syscall.RawSyscall(syscall.SYS_MKNODAT, uintptr(_AT_FDCWD), uintptr(unsafe.Pointer(p)), 0755)
				if err1 != 0 && err1 != syscall.EEXIST {
					goto childerror
				}
				break
			}
			_, _, err1 = syscall.RawSyscall(syscall.SYS_MKDIRAT, uintptr(_AT_FDCWD), uintptr(unsafe.Pointer(p)), 0755)
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
		// bind mount is not respect ro flag so that read-only bind mount needs remount
		if m.Flags&bindRo == bindRo {
			_, _, err1 = syscall.RawSyscall6(syscall.SYS_MOUNT, uintptr(unsafe.Pointer(&empty[0])),
				uintptr(unsafe.Pointer(m.Target)), uintptr(unsafe.Pointer(m.FsType)),
				uintptr(m.Flags|syscall.MS_REMOUNT), uintptr(unsafe.Pointer(m.Data)), 0)
			if err1 != 0 {
				goto childerror
			}
		}
	}

	// pivit_root
	if pivotRoot != nil {
		// mkdir("old_root")
		_, _, err1 = syscall.RawSyscall(syscall.SYS_MKDIRAT, uintptr(_AT_FDCWD), uintptr(unsafe.Pointer(&oldRoot[0])), 0755)
		if err1 != 0 {
			goto childerror
		}

		// pivot_root(root, "old_root")
		_, _, err1 = syscall.RawSyscall(syscall.SYS_PIVOT_ROOT, uintptr(unsafe.Pointer(pivotRoot)), uintptr(unsafe.Pointer(&oldRoot[0])), 0)
		if err1 != 0 {
			goto childerror
		}

		// umount("old_root", MNT_DETACH)
		_, _, err1 = syscall.RawSyscall(syscall.SYS_UMOUNT2, uintptr(unsafe.Pointer(&oldRoot[0])), syscall.MNT_DETACH, 0)
		if err1 != 0 {
			goto childerror
		}

		// rmdir("old_root")
		_, _, err1 = syscall.RawSyscall(syscall.SYS_UNLINKAT, uintptr(_AT_FDCWD), uintptr(unsafe.Pointer(&oldRoot[0])), uintptr(unix.AT_REMOVEDIR))
		if err1 != 0 {
			goto childerror
		}

		// mount("tmpfs", "/", "tmpfs", MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOATIME | MS_NOSUID, nil)
		_, _, err1 = syscall.RawSyscall6(syscall.SYS_MOUNT, uintptr(unsafe.Pointer(&tmpfs[0])),
			uintptr(unsafe.Pointer(&slash[0])), uintptr(unsafe.Pointer(&tmpfs[0])),
			uintptr(syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOATIME|syscall.MS_NOSUID),
			uintptr(unsafe.Pointer(&empty[0])), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// SetHostName
	if hostname != nil {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_SETHOSTNAME,
			uintptr(unsafe.Pointer(hostname)), uintptr(len(r.HostName)), 0)
	}

	// SetDomainName
	if domainname != nil {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_SETDOMAINNAME,
			uintptr(unsafe.Pointer(domainname)), uintptr(len(r.DomainName)), 0)
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
		// prlimit instead of setrlimit to avoid 32-bit limitation (linux > 3.2)
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

	// Drop all capabilities
	if r.DropCaps {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&dropCapHeader)), uintptr(unsafe.Pointer(&dropCapData)), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Enable Ptrace & sync with parent (since ptrace_me is a blocking operation)
	if r.Ptrace && r.Seccomp != nil {
		err2 = 0
		r1, _, err1 = syscall.RawSyscall(syscall.SYS_WRITE, uintptr(pipe), uintptr(unsafe.Pointer(&err2)), uintptr(unsafe.Sizeof(err2)))
		if r1 == 0 || err1 != 0 {
			goto childerror
		}

		r1, _, err1 = syscall.RawSyscall(syscall.SYS_READ, uintptr(pipe), uintptr(unsafe.Pointer(&err2)), uintptr(unsafe.Sizeof(err2)))
		if r1 == 0 || err1 != 0 {
			goto childerror
		}

		_, _, err1 = syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_TRACEME), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// if both seccomp and ptrace is defined, then seccomp filter should have
	// traced execve, thus child need parent attached to it first
	// actually, this is not effective if pid namespace is unshared
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

	// Before exec, sync with parent through pipe (configured as close_on_exec)
	if !r.Ptrace || r.Seccomp == nil {
		err2 = 0
		r1, _, err1 = syscall.RawSyscall(syscall.SYS_WRITE, uintptr(pipe), uintptr(unsafe.Pointer(&err2)), uintptr(unsafe.Sizeof(err2)))
		if r1 == 0 || err1 != 0 {
			goto childerror
		}

		r1, _, err1 = syscall.RawSyscall(syscall.SYS_READ, uintptr(pipe), uintptr(unsafe.Pointer(&err2)), uintptr(unsafe.Sizeof(err2)))
		if r1 == 0 || err1 != 0 {
			goto childerror
		}
	}

	// Enable ptrace if no seccomp is needed
	if r.Ptrace && r.Seccomp == nil {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_TRACEME), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// at this point, runner is successfully attached for seccomp trap filter
	// or execve trapped without seccomp filter
	// time to exec
	// if execfile fd is specified, call fexecve
	if r.ExecFile > 0 {
		_, _, err1 = syscall.RawSyscall6(unix.SYS_EXECVEAT, r.ExecFile,
			uintptr(unsafe.Pointer(&empty[0])),
			uintptr(unsafe.Pointer(&argv[0])),
			uintptr(unsafe.Pointer(&env[0])), unix.AT_EMPTY_PATH, 0)
	} else {
		_, _, err1 = syscall.RawSyscall6(unix.SYS_EXECVEAT, uintptr(_AT_FDCWD),
			uintptr(unsafe.Pointer(argv0)),
			uintptr(unsafe.Pointer(&argv[0])),
			uintptr(unsafe.Pointer(&env[0])), 0, 0)
	}

childerror:
	// send error code on pipe
	syscall.RawSyscall(unix.SYS_WRITE, uintptr(pipe), uintptr(unsafe.Pointer(&err1)), unsafe.Sizeof(err1))
	for {
		syscall.RawSyscall(syscall.SYS_EXIT, uintptr(err1+err2), 0, 0)
	}
	// cannot reach this point
}
