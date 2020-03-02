package runner

import (
	"fmt"
	"time"
)

// Limit represents the resource limit for traced process
type Limit struct {
	TimeLimit   time.Duration // user CPU time limit (in ns)
	MemoryLimit Size          // user memory limit (in bytes)
}

func (l Limit) String() string {
	return fmt.Sprintf("Limit[Time=%v, Memory=%v]", l.TimeLimit, l.MemoryLimit)
}
