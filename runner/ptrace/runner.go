package ptrace

import (
	"syscall"

	"github.com/criyle/go-sandbox/pkg/rlimit"
	"github.com/criyle/go-sandbox/pkg/seccomp"
	"github.com/criyle/go-sandbox/ptracer"
	"github.com/criyle/go-sandbox/types"
)

// Runner defines the spec to run a program safely by ptracer
type Runner struct {
	// argv and env for the child process
	// work path set by setcwd (current working directory for child)
	Args    []string
	Env     []string
	WorkDir string

	// fexecve
	ExecFile uintptr

	// file disriptors for new process, from 0 to len - 1
	Files []uintptr

	// Resource limit set by set rlimit
	RLimits []rlimit.RLimit

	// Res limit enforced by tracer
	Limit types.Limit

	// Defines seccomp filter for the ptrace runner
	// file access syscalls need to set as ActionTrace
	// allowed need to set as ActionAllow
	// default action should be ActionTrace / ActionKill
	Seccomp seccomp.Filter

	// Traced syscall handler
	Handler Handler

	// ShowDetails / Unsafe debug flag
	ShowDetails, Unsafe bool

	// Use by cgroup to add proc
	SyncFunc func(pid int) error
}

// BanRet defines the return value for a syscall ban acction
var BanRet = syscall.EACCES

// Handler defines the action when a file access encountered
type Handler interface {
	CheckRead(string) ptracer.TraceAction
	CheckWrite(string) ptracer.TraceAction
	CheckStat(string) ptracer.TraceAction
	CheckSyscall(string) ptracer.TraceAction
}
