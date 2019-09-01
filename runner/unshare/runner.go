package unshare

import (
	"github.com/criyle/go-sandbox/pkg/mount"
	"github.com/criyle/go-sandbox/pkg/rlimit"
	"github.com/criyle/go-sandbox/pkg/seccomp"
	"github.com/criyle/go-sandbox/types"
)

// Runner runs program in unshared namespaces
type Runner struct {
	// argv and env for the child process
	Args []string
	Env  []string

	// fexecve param
	ExecFile uintptr

	// workdir is the current dir after unshare mount namespaces
	WorkDir string

	// file disriptors for new process, from 0 to len - 1
	Files []uintptr

	// Resource limit set by set rlimit
	RLimits rlimit.RLimits

	// Resource limit enforced by tracer
	Limit types.Limit

	// Seccomp defines the seccomp filter attach to the process (should be whitelist only)
	Seccomp seccomp.Filter

	// New root
	Root string

	// Mount syscalls
	Mounts []*mount.Mount

	// hostname & domainname
	HostName, DomainName string

	// Show Details
	ShowDetails bool

	// Use by cgroup to add proc
	SyncFunc func(pid int) error
}
