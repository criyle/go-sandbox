package tracer

// Tracer is the configuration for executing new process and trace its syscalls
// using libseccomp and ptrace
type Tracer struct {
	// Resource limit set by set rlimit
	TimeLimit     uint64 // second
	RealTimeLimit uint64 // second
	MemoryLimit   uint64 // mb
	OutputLimit   uint64 // mb
	StackLimit    uint64 // mb

	// stdin, stdout, stderr file name. nil for default
	InputFileName  string
	OutputFileName string
	ErrorFileName  string

	// work path
	WorkPath string

	// argv and env for the child process
	Args []string
	Env  []string

	// whether to output debug information
	ShowDetails bool
	Unsafe      bool

	// seccomp config
	// if one syscall exists in both allow and trace, trace will overwrite it
	Allow []string
	Trace []string

	// if no handle, then default one is allow
	TraceHandle func(*Context) TraceAction
}

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
	TraceCodeInvalid TraceCode = iota
	TraceCodeTLE
	TraceCodeMLE
	TraceCodeOLE
	TraceCodeBan
	TraceCodeRE
	TraceCodeFatal
)

func (t TraceCode) Error() string {
	switch t {
	case TraceCodeTLE:
		return "time limit exceeded"
	case TraceCodeMLE:
		return "memory limit exceeded"
	case TraceCodeOLE:
		return "output limit exceeded"
	case TraceCodeBan:
		return "syscall banned"
	case TraceCodeRE:
		return "runtime error"
	case TraceCodeFatal:
		return "handle failed"
	default:
		return "invalid"
	}
}

// TraceResult is the result returned by strat trace
type TraceResult struct {
	UserTime, UserMem uint64
}

// NewTracer return new Tracer with default setting
func NewTracer() Tracer {
	allow := make([]string, len(defaultAllows))
	copy(allow, defaultAllows)

	trace := make([]string, len(defaultTraces))
	copy(trace, defaultTraces)
	// default settings
	return Tracer{
		TimeLimit:     1,
		RealTimeLimit: 0,
		MemoryLimit:   256,
		OutputLimit:   64,
		StackLimit:    1024,

		Allow: allow,
		Trace: trace,
	}
}
