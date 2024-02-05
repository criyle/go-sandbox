package cgroup

// Cgroup constants
const (
	// systemd mounted cgroups
	basePath        = "/sys/fs/cgroup"
	cgroupProcs     = "cgroup.procs"
	procCgroupsPath = "/proc/cgroups"
	procSelfCgroup  = "/proc/self/cgroup"

	cgroupSubtreeControl = "cgroup.subtree_control"
	cgroupControllers    = "cgroup.controllers"

	filePerm = 0644
	dirPerm  = 0755

	CPU     = "cpu"
	CPUAcct = "cpuacct"
	CPUSet  = "cpuset"
	Memory  = "memory"
	Pids    = "pids"
)

// Type defines the version of cgroup
type Type int

// Type enum for cgroup
const (
	TypeV1 = iota + 1
	TypeV2
)

func (t Type) String() string {
	switch t {
	case TypeV1:
		return "v1"
	case TypeV2:
		return "v2"
	default:
		return "invalid"
	}
}
