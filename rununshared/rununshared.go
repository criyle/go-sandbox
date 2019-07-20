package rununshared

import (
	"github.com/criyle/go-judger/types/mount"
	"github.com/criyle/go-judger/types/rlimit"
	"github.com/criyle/go-judger/types/specs"
)

// RunUnshared runs program in unshared namespaces
type RunUnshared struct {
	// argv and env for the child process
	Args []string
	Env  []string

	// workdir is the current dir after unshare mount namespaces
	WorkDir string

	// file disriptors for new process, from 0 to len - 1
	Files []uintptr

	// Resource limit set by set rlimit
	RLimits rlimit.RLimits

	// Resource limit enforced by tracer
	ResLimits specs.ResLimit

	// Allowed syscall names
	SyscallAllowed []string

	// New root
	Root string

	// Mount syscalls
	Mounts []*mount.Mount

	// Show Details
	ShowDetails bool
}
