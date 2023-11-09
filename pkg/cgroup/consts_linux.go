package cgroup

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

type CgroupType int

const (
	CgroupTypeV1 = iota + 1
	CgroupTypeV2
)

func (t CgroupType) String() string {
	switch t {
	case CgroupTypeV1:
		return "v1"
	case CgroupTypeV2:
		return "v2"
	default:
		return "invalid"
	}
}
