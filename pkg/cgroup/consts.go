package cgroup

const (
	// systemd mounted cgroups
	basePath        = "/sys/fs/cgroup"
	cgroupProcs     = "cgroup.procs"
	cgroupControl   = "cgroup.subtree_control"
	procCgroupsPath = "/proc/cgroups"

	filePerm = 0644
	dirPerm  = 0755
)
