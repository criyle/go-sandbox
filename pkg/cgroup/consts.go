package cgroup

const (
	// systemd mounted cgroups
	basePath        = "/sys/fs/cgroup"
	cgroupProcs     = "cgroup.procs"
	procCgroupsPath = "/proc/cgroups"

	filePerm = 0644
)
