package tracer

// TraceAction defines the action returned by TraceHandle
type TraceAction int

const (
	// TraceAllow does not do anything
	TraceAllow TraceAction = iota
	// TraceBan blocked the syscall and set the return code specified by SetReturnCode
	TraceBan
	// TraceKill refered as dangerous action have been detacted
	TraceKill
)

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
