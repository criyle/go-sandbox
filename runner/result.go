package runner

import (
	"fmt"
	"time"
)

// Result is the program runner result
type Result struct {
	Status            // result status
	ExitStatus int    // exit status (signal number if signalled)
	Error      string // potential detailed error message (for program runner error)

	Time   time.Duration // used user CPU time  (underlying type int64 in ns)
	Memory Size          // used user memory    (underlying type uint64 in bytes)

	// metrics for the program runner
	SetUpTime   time.Duration
	RunningTime time.Duration
}

func (r Result) String() string {
	switch r.Status {
	case StatusNormal:
		return fmt.Sprintf("Result[%v %v][%v %v]", r.Time, r.Memory, r.SetUpTime, r.RunningTime)

	case StatusSignalled:
		return fmt.Sprintf("Result[Signalled(%d)][%v %v][%v %v]", r.ExitStatus, r.Time, r.Memory, r.SetUpTime, r.RunningTime)

	case StatusRunnerError:
		return fmt.Sprintf("Result[RunnerFailed(%s)][%v %v][%v %v]", r.Error, r.Time, r.Memory, r.SetUpTime, r.RunningTime)

	default:
		return fmt.Sprintf("Result[%v(%s %d)][%v %v][%v %v]", r.Status, r.Error, r.ExitStatus, r.Time, r.Memory, r.SetUpTime, r.RunningTime)
	}
}
