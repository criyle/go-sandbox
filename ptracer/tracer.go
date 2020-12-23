package ptracer

import "github.com/criyle/go-sandbox/runner"

// TraceAction defines the action returned by TraceHandle
type TraceAction int

const (
	// TraceAllow does not do anything
	TraceAllow TraceAction = iota
	// TraceBan skippes the syscall and set the return code specified by SetReturnCode
	TraceBan
	// TraceKill referred as dangerous action have been detected
	TraceKill
)

// Tracer defines a ptracer instance
type Tracer struct {
	Handler
	Runner
	runner.Limit
}

// Runner represents the process runner
type Runner interface {
	// Starts starts the child process and return pid and error if failed
	// the child process should enable ptrace and should stop before ptrace
	Start() (int, error)
}

// Handler defines customized handler for traced syscall
type Handler interface {
	// Handle returns action take to the traced program
	Handle(*Context) TraceAction

	// Debug prints debug information when in debug mode
	Debug(v ...interface{})
}
