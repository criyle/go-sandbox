package cgroup

// Cgroup defines the common interface to control cgroups
// including v1 and v2 implementations.
// TODO: implement systemd integration
type Cgroup interface {
	// AddProc add a process into the cgroup
	AddProc(pid int) error

	// Destroy deletes the cgroup
	Destroy() error

	// CPUUsage reads total cpu usage of cgroup
	CPUUsage() (uint64, error)

	// MemoryUsage reads current total memory usage
	MemoryUsage() (uint64, error)

	// MemoryMaxUsageInBytes reads max total memory usage. Not exist in cgroup v2
	MemoryMaxUsage() (uint64, error)

	// SetCPUBandwidth sets the cpu bandwidth. Times in ns
	SetCPUBandwidth(quota, period uint64) error

	// SetCpusetCpus sets the availabile cpu to use (cpuset.cpus).
	SetCPUSet([]byte) error

	// SetMemoryLimit sets memory.limit_in_bytes
	SetMemoryLimit(uint64) error

	// SetProcLimit sets pids.max
	SetProcLimit(uint64) error
}
