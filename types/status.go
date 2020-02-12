package types

// Status is the result Status
type Status int

// Result Status for program runner
const (
	StatusInvalid Status = iota // 0 not initialized
	// Normal
	StatusNormal // 1 normal

	// Resource Limit Exceeded
	StatusTimeLimitExceeded   // 2 tle
	StatusMemoryLimitExceeded // 3 mle
	StatusOutputLimitExceeded // 4 ole

	// Unauthorized Access
	StatusDisallowedSyscall // 5 ban

	// Runtime Error
	StatusSignalled         // 6 signalled
	StatusNonzeroExitStatus // 7 nonzero exit status

	// Programmer Runner Error
	StatusRunnerError // 8 runner error
)

var (
	statusString = []string{
		"Invalid",
		"",
		"Time Limit Exceeded",
		"Memory Limit Exceeded",
		"Output Limit Exceeded",
		"Disallowed Syscall",
		"Signalled",
		"Nonzero Exit Status",
		"Runner Error",
	}
)

func (t Status) String() string {
	i := int(t)
	if i >= 0 && i < len(statusString) {
		return statusString[i]
	}
	return statusString[0]
}

func (t Status) Error() string {
	return t.String()
}
