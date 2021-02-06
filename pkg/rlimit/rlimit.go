// Package rlimit provides data structure for resource limits by setrlimit syscall on linux.
package rlimit

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/criyle/go-sandbox/runner"
)

// RLimits defines the rlimit applied by setrlimit syscall to traced process
type RLimits struct {
	CPU          uint64 // in s
	CPUHard      uint64 // in s
	Data         uint64 // in bytes
	FileSize     uint64 // in bytes
	Stack        uint64 // in bytes
	AddressSpace uint64 // in bytes
	DisableCore  bool   // set core to 0
}

// RLimit is the resource limits defined by Linux setrlimit
type RLimit struct {
	// Res is the resource type (e.g. syscall.RLIMIT_CPU)
	Res int
	// Rlim is the limit applied to that resource
	Rlim syscall.Rlimit
}

func getRlimit(cur, max uint64) syscall.Rlimit {
	return syscall.Rlimit{Cur: cur, Max: max}
}

// PrepareRLimit creates rlimit structures for tracee
// TimeLimit in s, SizeLimit in byte
func (r *RLimits) PrepareRLimit() []RLimit {
	var ret []RLimit
	if r.CPU > 0 {
		cpuHard := r.CPUHard
		if cpuHard < r.CPU {
			cpuHard = r.CPU
		}

		ret = append(ret, RLimit{
			Res:  syscall.RLIMIT_CPU,
			Rlim: getRlimit(r.CPU, cpuHard),
		})
	}
	if r.Data > 0 {
		ret = append(ret, RLimit{
			Res:  syscall.RLIMIT_DATA,
			Rlim: getRlimit(r.Data, r.Data),
		})
	}
	if r.FileSize > 0 {
		ret = append(ret, RLimit{
			Res:  syscall.RLIMIT_FSIZE,
			Rlim: getRlimit(r.FileSize, r.FileSize),
		})
	}
	if r.Stack > 0 {
		ret = append(ret, RLimit{
			Res:  syscall.RLIMIT_STACK,
			Rlim: getRlimit(r.Stack, r.Stack),
		})
	}
	if r.AddressSpace > 0 {
		ret = append(ret, RLimit{
			Res:  syscall.RLIMIT_AS,
			Rlim: getRlimit(r.AddressSpace, r.AddressSpace),
		})
	}
	if r.DisableCore {
		ret = append(ret, RLimit{
			Res:  syscall.RLIMIT_CORE,
			Rlim: getRlimit(0, 0),
		})
	}
	return ret
}

func (r RLimit) String() string {
	if r.Res == syscall.RLIMIT_CPU {
		return fmt.Sprintf("CPU[%d s:%d s]", r.Rlim.Cur, r.Rlim.Max)
	}
	t := ""
	switch r.Res {
	case syscall.RLIMIT_DATA:
		t = "Data"
	case syscall.RLIMIT_FSIZE:
		t = "File"
	case syscall.RLIMIT_STACK:
		t = "Stack"
	case syscall.RLIMIT_AS:
		t = "AddressSpace"
	case syscall.RLIMIT_CORE:
		t = "Core"
	}
	return fmt.Sprintf("%s[%v:%v]", t, runner.Size(r.Rlim.Cur), runner.Size(r.Rlim.Max))
}

func (r RLimits) String() string {
	var sb strings.Builder
	sb.WriteString("RLimits[")
	for i, rl := range r.PrepareRLimit() {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(rl.String())
	}
	sb.WriteString("]")
	return sb.String()
}
