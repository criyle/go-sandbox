package types

// Status is the result Status
type Status int

// Different end condtion
const (
	StatusNormal  Status = iota // 0
	StatusInvalid               // 1
	StatusRE                    // 2
	StatusMLE                   // 3
	StatusTLE                   // 4
	StatusOLE                   // 5
	StatusBan                   // 6
	StatusFatal                 // 7
)

var (
	statusString = []string{
		"",
		"invalid",
		"runtime error",
		"memory limit exceeded",
		"time limit exceeded",
		"output limit exceeded",
		"syscall banned",
		"runner failed",
	}
)

func (t Status) String() string {
	i := int(t)
	if i >= 0 && i < len(statusString) {
		return statusString[i]
	}
	return "invalid"
}

func (t Status) Error() string {
	return t.String()
}
