package forkexec

import (
	"syscall"

	"github.com/criyle/go-sandbox/pkg/mount"
	"github.com/criyle/go-sandbox/pkg/rlimit"
)

// Runner is the configuration including the exec path, argv
// and resource limits. It can creates tracee for ptrace-based tracer.
// It can also create unshared process in another namespace
type Runner struct {
	// argv and env for execve syscall for the child process
	Args []string
	Env  []string

	// if exec_fd is defined, then at the end, fd_execve is called
	ExecFile uintptr

	// POSIX Resource limit set by set rlimit
	RLimits []rlimit.RLimit

	// file disriptors map for new process, from 0 to len - 1
	Files []uintptr

	// work path set by chdir(dir) (current working directory for child)
	// if pivot_root is defined, this will execute after changed to new root
	WorkDir string

	// seccomp syscall filter applied to child
	Seccomp *syscall.SockFprog

	// clone unshare flag to create linux namespace, effective when clone child
	// since unshare syscall does not join the new pid group
	CloneFlags uintptr

	// mounts defines the mount syscalls after unshare mount namespace
	// need CAP_SYS_ADMIN inside the namespace (e.g. unshare user namespace)
	// if pivot root is provided, relative target is better for chdir-mount meta
	// and pivot root will mount as tmpfs before any mount
	Mounts []mount.SyscallParams

	// pivot_root defines a readonly new root after unshare mount namespace
	// it should be a directory in absolute path and should used with mounts
	// Call path:
	// mount("tmpfs", root, "tmpfs", 0, nil)
	// chdir(root)
	// [do mounts]
	// mkdir("old_root")
	// pivot_root(root, "old_root")
	// umount("old_root", MNT_DETACH)
	// rmdir("old_root")
	// mount("tmpfs", "/", "tmpfs", MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOATIME | MS_NOSUID, nil)
	PivotRoot string

	// HostName and DomainName to be set after unshare UTS & user (CAP_SYS_ADMIN)
	HostName, DomainName string

	// UidMappings / GidMappings for unshared user namespaces, no-op if mapping is null
	UIDMappings []syscall.SysProcIDMap
	GIDMappings []syscall.SysProcIDMap

	// Credential holds user and group identities to be assumed
	// by a child process started by StartProcess.
	Credential *syscall.Credential

	// Parent and child process with sync sataus through a socket pair.
	// SyncFunc will invoke with the child pid. If SyncFunc return some error,
	// parent will signal child to stop and report the error
	// SyncFunc is called right before execve, thus it could track cpu more accurately
	SyncFunc func(int) error

	// ptrace controls child process to call ptrace(PTRACE_TRACEME)
	// runtime.LockOSThread is required for tracer to call ptrace syscalls
	Ptrace bool

	// no_new_privs calls prctl(PR_SET_NO_NEW_PRIVS) to 0 to disable calls to
	// setuid processes. It is automatically enabled when seccomp filter is provided
	NoNewPrivs bool

	// stop before seccomp calls kill(getpid(), SIGSTOP) to wait for tracer to continue
	// right before the calls to seccomp. It is automatically enabled when seccomp
	// filter and ptrace are provided since kill might not be available after
	// seccomp and execve might be traced by ptrace
	// cannot stop after seccomp since kill might not be allowed by seccomp filter
	StopBeforeSeccomp bool

	// GidMappingsEnableSetgroups allows / disallows setgroups syscall.
	// deny if GIDMappings is nil
	GIDMappingsEnableSetgroups bool

	// drop_caps calls cap_set(self, 0) to drop all capabilities
	// from effective, permitted, inheritable capability sets before execve
	// it should avoid calls to set ambient capabilities
	DropCaps bool

	// UnshareCgroupAfterSync specifies whether to unshare cgroup namespace after
	// sync (the syncFunc might be add the child to the cgroup)
	UnshareCgroupAfterSync bool

	// CTTY specifies if set the fd 0 as controlling TTY
	CTTY bool
}
