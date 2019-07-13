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

// TraceCode is the error type
type TraceCode int

// Different end condtion
const (
	TraceCodeNormal  TraceCode = iota // 0
	TraceCodeInvalid                  // 1
	TraceCodeRE                       // 2
	TraceCodeMLE                      // 3
	TraceCodeTLE                      // 4
	TraceCodeOLE                      // 5
	TraceCodeBan                      // 6
	TraceCodeFatal                    // 7
)

func (t TraceCode) Error() string {
	switch t {
	case TraceCodeNormal:
		return ""
	case TraceCodeRE:
		return "runtime error"
	case TraceCodeTLE:
		return "time limit exceeded"
	case TraceCodeMLE:
		return "memory limit exceeded"
	case TraceCodeOLE:
		return "output limit exceeded"
	case TraceCodeBan:
		return "syscall banned"
	case TraceCodeFatal:
		return "handle failed"
	default:
		return "invalid"
	}
}

// TraceResult is the result returned by strat trace
type TraceResult struct {
	UserTime    uint64    // used user CPU time (in ms)
	UserMem     uint64    // used user memory (in kb)
	ExitCode    int       // exit code
	TraceStatus TraceCode // the final status for the process
}

// Runner represents the process runner
type Runner interface {
	// Starts starts the child process and return pid and error if failed
	Start() (int, error)
}

// ResLimit represents the resource limit for traced process
type ResLimit struct {
	TimeLimit     uint64 // user CPU time limit (in ms)
	RealTimeLimit uint64 // sig_kill will force the process to exit after this limit (in ms)
	MemoryLimit   uint64 // user memory limit (in kB)
}

// Handler defines customized handler for traced syscall
type Handler interface {
	Handle(*Context) TraceAction
	GetSyscallName(*Context) (string, error)

	Debug(v ...interface{})
	HandlerDisallow(string) error
}
