//go:build linux || darwin

// Package rlimit provides data structures for resource limits applied with
// setrlimit/prlimit.
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
	CPUHard      uint64 // hard CPU limit in s; if CPU is zero, also becomes the soft limit
	Data         uint64 // in bytes; zero means unspecified
	FileSize     uint64 // in bytes; zero means unspecified
	Stack        uint64 // in bytes; zero means unspecified
	AddressSpace uint64 // in bytes; zero means unspecified
	OpenFile     uint64 // count; zero means unspecified
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

// PrepareRLimit creates rlimit structures for the tracee.
// Time limits are in seconds and size limits are in bytes. A zero-valued
// numeric limit means unspecified, except that CPUHard is used as both the
// soft and hard CPU limit when CPU is zero. On macOS, DATA and AS limits may
// be rejected by setrlimit and are intentionally ignored by the Darwin
// forkexec runner.
func (r *RLimits) PrepareRLimit() []RLimit {
	ret := make([]RLimit, 0, 7)
	if r.CPU > 0 || r.CPUHard > 0 {
		cpuSoft := r.CPU
		if cpuSoft == 0 {
			cpuSoft = r.CPUHard
		}
		cpuHard := max(r.CPUHard, cpuSoft)

		ret = append(ret, RLimit{
			Res:  syscall.RLIMIT_CPU,
			Rlim: getRlimit(cpuSoft, cpuHard),
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
	if r.OpenFile > 0 {
		ret = append(ret, RLimit{
			Res:  syscall.RLIMIT_NOFILE,
			Rlim: getRlimit(r.OpenFile, r.OpenFile),
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
	t := ""
	switch r.Res {
	case syscall.RLIMIT_CPU:
		return fmt.Sprintf("CPU[%d s:%d s]", r.Rlim.Cur, r.Rlim.Max)
	case syscall.RLIMIT_NOFILE:
		return fmt.Sprintf("OpenFile[%d:%d]", r.Rlim.Cur, r.Rlim.Max)
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
