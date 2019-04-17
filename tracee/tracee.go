// Package tracee provides interface to run a seccomp filtered, rlimited
// executable and ptraced
package tracee

import "syscall"

// Runner is the RunProgramConfig including the exec path, argv
// and resource limits. It creates tracee for ptrace-based tracer.
type Runner struct {
	// argv and env for the child process
	Args []string
	Env  []string

	// Resource limit set by set rlimit
	RLimits []RLimit

	// file disriptors for new process, from 0 to len - 1
	Files []uintptr

	// work path set by setcwd (current working directory for child)
	WorkDir string

	// BPF syscall filter applied to child
	BPF *syscall.SockFprog
}

// RLimit is the resource limits defined by Linux setrlimit
type RLimit struct {
	// Res is the resource type (e.g. syscall.RLIMIT_CPU)
	Res int
	// Rlim is the limit applied to that resource
	Rlim syscall.Rlimit
}

// NewRunner creates new runner struct
func NewRunner() Runner {
	return Runner{}
}
