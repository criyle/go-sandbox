package runprogram

import (
	"syscall"

	"github.com/criyle/go-judger/tracer"
)

// RunProgram defines the spec to run a program safely
type RunProgram struct {
	// argv and env for the child process
	// work path set by setcwd (current working directory for child)
	Args    []string
	Env     []string
	WorkDir string

	// file disriptors for new process, from 0 to len - 1
	Files []uintptr

	// Resource limit set by set rlimit
	RLimits RLimits

	// Res limit enforced by tracer
	TraceLimit TraceLimit

	// Allowed / Traced syscall names
	// Notice: file access syscalls should be traced
	// If traced syscall is file access, it will checked by file access handler
	// otherwise it will checked by syscall access handler
	SyscallAllowed []string
	SyscallTraced  []string

	// Traced syscall handler
	Handler Handler

	// ShowDetails / Unsafe debug flag
	ShowDetails, Unsafe bool
}

// TraceLimit defines the limits enforced by tracer
type TraceLimit tracer.ResLimit

// TraceAction defines action against a syscall check
type TraceAction int

// BanRet defines the return value for a syscall ban acction
var BanRet syscall.Errno = syscall.EACCES

// TraceAllow allow the access, trace ban ignores the syscall and set the
// return value to BanRet, TraceKill stops the trace action
const (
	TraceAllow = iota + 1
	TraceBan
	TraceKill
)

// Handler defines the action when a file access encountered
type Handler interface {
	CheckRead(string) TraceAction
	CheckWrite(string) TraceAction
	CheckStat(string) TraceAction
	CheckSyscall(string) TraceAction
}
