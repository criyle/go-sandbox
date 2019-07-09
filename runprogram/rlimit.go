package runprogram

import (
	"syscall"

	"github.com/criyle/go-judger/forkexec"
)

// RLimits defines the rlimit applied by setrlimit syscall to traced process
type RLimits struct {
	CPU          uint // in s
	CPUHard      uint // in s
	Data         uint // in kb
	FileSize     uint // in kb
	Stack        uint // in kb
	AddressSpace uint // in kb
}

func getRlimit(cur, max uint64) syscall.Rlimit {
	return syscall.Rlimit{Cur: uint64(cur), Max: uint64(max)}
}

// prepareRLimit creates rlimit structures for tracee
// TimeLimit in s, SizeLimit in byte
func (r *RLimits) prepareRLimit() []forkexec.RLimit {
	var ret []forkexec.RLimit
	if r.CPU > 0 {
		cpuHard := r.CPUHard
		if cpuHard < r.CPU {
			cpuHard = r.CPU
		}

		ret = append(ret, forkexec.RLimit{
			Res:  syscall.RLIMIT_CPU,
			Rlim: getRlimit(uint64(r.CPU), uint64(cpuHard)),
		})
	}
	if r.Data > 0 {
		ret = append(ret, forkexec.RLimit{
			Res:  syscall.RLIMIT_DATA,
			Rlim: getRlimit(uint64(r.Data)<<10, uint64(r.Data)<<10),
		})
	}
	if r.FileSize > 0 {
		ret = append(ret, forkexec.RLimit{
			Res:  syscall.RLIMIT_FSIZE,
			Rlim: getRlimit(uint64(r.FileSize)<<10, uint64(r.FileSize)<<10),
		})
	}
	if r.Stack > 0 {
		ret = append(ret, forkexec.RLimit{
			Res:  syscall.RLIMIT_STACK,
			Rlim: getRlimit(uint64(r.Stack)<<10, uint64(r.Stack)<<10),
		})
	}
	if r.AddressSpace > 0 {
		ret = append(ret, forkexec.RLimit{
			Res:  syscall.RLIMIT_AS,
			Rlim: getRlimit(uint64(r.AddressSpace)<<10, uint64(r.AddressSpace)<<10),
		})
	}
	return ret
}
