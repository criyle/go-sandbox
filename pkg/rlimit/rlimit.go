package rlimit

import (
	"syscall"
)

// RLimits defines the rlimit applied by setrlimit syscall to traced process
type RLimits struct {
	CPU          uint64 // in s
	CPUHard      uint64 // in s
	Data         uint64 // in bytes
	FileSize     uint64 // in bytes
	Stack        uint64 // in bytes
	AddressSpace uint64 // in bytes
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
	return ret
}
