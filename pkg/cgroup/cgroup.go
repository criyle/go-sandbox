// Package cgroup provices basic resource control over cgroups
// it measure
//   cpu: cpuacct.usage (ns)
//   memory: memory.max_usage_in_bytes
// it limits:
//   memory: memory.limit_in_bytes
//   # of tasks: pids.max
package cgroup

import "os"

// additional ideas:
//   cpu share(not used): cpu.share
//   reclaim pages from old process: memory.force_empty
//   (tasks kill are managed out of cgroup as freeze takes some time)
//   freeze: freezer.state

// CGroup is the combination of sub-cgroups
type CGroup struct {
	prefix                string
	cpuacct, memory, pids *SubCGroup
}

// NewCGroup creates new cgrouup directories
func NewCGroup(prefix string) (*CGroup, error) {
	cpuacctPath, err := CreateSubCGroupPath("cpuacct", prefix)
	if err != nil {
		return nil, err
	}
	memoryPath, err := CreateSubCGroupPath("memory", prefix)
	if err != nil {
		return nil, err
	}
	pidsPath, err := CreateSubCGroupPath("pids", prefix)
	if err != nil {
		return nil, err
	}
	return &CGroup{
		prefix:  prefix,
		cpuacct: NewSubCGroup(cpuacctPath),
		memory:  NewSubCGroup(memoryPath),
		pids:    NewSubCGroup(pidsPath),
	}, nil
}

// AddProc writes cgroup.procs to all sub-cgroup
func (c *CGroup) AddProc(pid int) error {
	if err := c.cpuacct.WriteUint(cgroupProcs, uint64(pid)); err != nil {
		return err
	}
	if err := c.memory.WriteUint(cgroupProcs, uint64(pid)); err != nil {
		return err
	}
	if err := c.pids.WriteUint(cgroupProcs, uint64(pid)); err != nil {
		return err
	}
	return nil
}

// Destroy removes dir for sub-cggroup
func (c *CGroup) Destroy() error {
	if err := os.Remove(c.cpuacct.path); err != nil {
		return err
	}
	if err := os.Remove(c.memory.path); err != nil {
		return err
	}
	if err := os.Remove(c.pids.path); err != nil {
		return err
	}
	return nil
}

// CpuacctUsage read cpuacct.usage in ns
func (c *CGroup) CpuacctUsage() (uint64, error) {
	return c.cpuacct.ReadUint("cpuacct.usage")
}

// MemoryMaxUsageInBytes read memory.max_usage_in_bytes
func (c *CGroup) MemoryMaxUsageInBytes() (uint64, error) {
	return c.memory.ReadUint("memory.max_usage_in_bytes")
}

// SetMemoryLimitInBytes write memory.limit_in_bytes
func (c *CGroup) SetMemoryLimitInBytes(i uint64) error {
	return c.memory.WriteUint("memory.limit_in_bytes", i)
}

// SetPidsMax write pids.max
func (c *CGroup) SetPidsMax(i uint64) error {
	return c.pids.WriteUint("pids.max", i)
}
