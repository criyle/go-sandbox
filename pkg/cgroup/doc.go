// Package cgroup provices builder to create multiple different cgroup-v1 sub groups
// under systemd defined path (i.e. /sys/fs/cgroup).
//
// current available cgroups are cpuacct, memory, pids
// not available: cpu, cpuset, devices, freezer, net_cls, blkio, perf_event, net_prio, huge_tlb, rdma
package cgroup
