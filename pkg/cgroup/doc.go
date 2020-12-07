// Package cgroup provices builder to create multiple different cgroup-v1 sub groups
// under systemd defined mount path (i.e.,sys/fs/cgroup).
//
// Current available:
//  cpuacct
//  memory
//  pids
//  cpuset
//
// Current not available: cpu, cpuset, devices, freezer, net_cls, blkio, perf_event, net_prio, huge_tlb, rdma
//
// Additional ideas:
//
//   cpu share(not used): cpu.share
//   reclaim pages from old process: memory.force_empty
//   (tasks kill are managed out of cgroup as freeze takes some time)
//   freeze: freezer.state
package cgroup
