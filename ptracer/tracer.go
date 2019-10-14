package ptracer

import "github.com/criyle/go-sandbox/types"

// TraceAction defines the action returned by TraceHandle
type TraceAction int

const (
	// TraceAllow does not do anything
	TraceAllow TraceAction = iota
	// TraceBan blocked the syscall and set the return code specified by SetReturnCode
	TraceBan
	// TraceKill referred as dangerous action have been detected
	TraceKill
)

// Tracer defines a ptracer instance
type Tracer struct {
	Handler
	Runner
	types.Limit
}

// Runner represents the process runner
type Runner interface {
	// Starts starts the child process and return pid and error if failed
	Start() (int, error)
}

// Handler defines customized handler for traced syscall
type Handler interface {
	Handle(*Context) TraceAction
	GetSyscallName(*Context) (string, error)

	Debug(v ...interface{})
	HandlerDisallow(string) error
}
