// Package forkexec provides interface to run a seccomp filtered, rlimited
// executable and ptraced
package forkexec

import (
	"syscall"

	"github.com/criyle/go-judger/mount"
)

// Runner is the RunProgramConfig including the exec path, argv
// and resource limits. It creates tracee for ptrace-based tracer.
// It can also create unshared process in another namespace
type Runner struct {
	// argv and env for execve syscall for the child process
	Args []string
	Env  []string

	// Resource limit set by set rlimit
	RLimits []RLimit

	// file disriptors for new process, from 0 to len - 1
	Files []uintptr

	// work path set by chdir(dir) (current working directory for child)
	// if pivot_root is defined, this will execute after changed to new root
	WorkDir string

	// seccomp syscall filter applied to child
	Seccomp *syscall.SockFprog

	// ptrace controls child process to call ptrace(PTRACE_TRACEME)
	// runtime.LockOSThread is required for tracer to call ptrace syscalls
	Ptrace bool

	// no_new_privs calls ptctl(PR_SET_NO_NEW_PRIVS) to 0 to disable calls to
	// setuid processes. It is automatically enabled when seccomp filter is provided
	NoNewPrivs bool

	// stop before seccomp calls kill(getpid(), SIGSTOP) to wait for tracer to continue
	// right before the calls to seccomp. It is automatically enabled when seccomp
	// filter and ptrace are provided since kill might not be avaliable after
	// seccomp and execve might be traced by ptrace
	StopBeforeSeccomp bool

	// stop before exec calls kill(getpid(), SIGSTOP) to wait for tracer to continue
	// right before the final calls to execve. It acts as a synchronize
	// for parent process
	StopBeforeExec bool

	// unshare flag to create linux namespace, effective when clone child
	// since unshare syscall does not join the new pid group
	UnshareFlags uintptr

	// mounts defines the mount syscalls after unshare mount namespace
	// need CAP_ADMIN inside the namespace (e.g. unshare user namespace)
	// if pivot root is provided, relative target will based on PivotRoot directory
	// and pivot root will mount as tmpfs before any mount
	Mounts []*mount.Mount

	// pivot_root defines the new root after unshare mount namespace
	// root need to be a mount point (e.g. defined in Mounts) and it should
	// be a absolute path
	// It will call:
	// mkdir(root/old_root)
	// pivot_root(root, root/old_root)
	// umount(root/old, MNT_DETACH)
	// rmdir(root/old_root)
	PivotRoot string

	// drop_caps calls cap_set(self, 0) to drop all capabilities
	// from effective, permitted, inheritable capability sets before execve
	// it should avoid calls to set
	DropCaps bool
}
