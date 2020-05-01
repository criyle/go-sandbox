package forkexec

import (
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

	// sandbox profile defines the sandbox profile for sandbox_init syscall
	SandboxProfile string

	// Parent and child process with sync sataus through a socket pair.
	// SyncFunc will invoke with the child pid. If SyncFunc return some error,
	// parent will signal child to stop and report the error
	// SyncFunc is called right before execve, thus it could track cpu more accurately
	SyncFunc func(int) error
}
