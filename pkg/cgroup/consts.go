package cgroup

const (
	// systemd mounted cgroups
	basePath        = "/sys/fs/cgroup"
	cgroupProcs     = "cgroup.procs"
	procCgroupsPath = "/proc/cgroups"

	cgroupSubtreeControl = "cgroup.subtree_control"
	cgroupControllers    = "cgroup.controllers"

	filePerm = 0644
	dirPerm  = 0755
)
