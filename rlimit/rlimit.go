package rlimit

import (
	"syscall"

	"github.com/criyle/go-judger/forkexec"
)

// RLimits defines the rlimit applied by setrlimit syscall to traced process
type RLimits struct {
	CPU          uint64 // in s
	CPUHard      uint64 // in s
	Data         uint64 // in kb
	FileSize     uint64 // in kb
	Stack        uint64 // in kb
	AddressSpace uint64 // in kb
}

func getRlimit(cur, max uint64) syscall.Rlimit {
	return syscall.Rlimit{Cur: uint64(cur), Max: uint64(max)}
}

// PrepareRLimit creates rlimit structures for tracee
// TimeLimit in s, SizeLimit in byte
func (r *RLimits) PrepareRLimit() []forkexec.RLimit {
	var ret []forkexec.RLimit
	if r.CPU > 0 {
		cpuHard := r.CPUHard
		if cpuHard < r.CPU {
			cpuHard = r.CPU
		}

		ret = append(ret, forkexec.RLimit{
			Res:  syscall.RLIMIT_CPU,
			Rlim: getRlimit(r.CPU, cpuHard),
		})
	}
	if r.Data > 0 {
		ret = append(ret, forkexec.RLimit{
			Res:  syscall.RLIMIT_DATA,
			Rlim: getRlimit(r.Data<<10, r.Data<<10),
		})
	}
	if r.FileSize > 0 {
		ret = append(ret, forkexec.RLimit{
			Res:  syscall.RLIMIT_FSIZE,
			Rlim: getRlimit(r.FileSize<<10, r.FileSize<<10),
		})
	}
	if r.Stack > 0 {
		ret = append(ret, forkexec.RLimit{
			Res:  syscall.RLIMIT_STACK,
			Rlim: getRlimit(r.Stack<<10, r.Stack<<10),
		})
	}
	if r.AddressSpace > 0 {
		ret = append(ret, forkexec.RLimit{
			Res:  syscall.RLIMIT_AS,
			Rlim: getRlimit(r.AddressSpace<<10, r.AddressSpace<<10),
		})
	}
	return ret
}
