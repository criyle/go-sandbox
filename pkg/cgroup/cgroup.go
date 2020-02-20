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

// Build creates new cgrouup directories
func (b *Builder) Build() (cg *CGroup, err error) {
	var (
		cpuacctPath, memoryPath, pidsPath string
	)
	// if failed, remove potential created directory
	defer func() {
		if err != nil {
			remove(cpuacctPath)
			remove(memoryPath)
			remove(pidsPath)
		}
	}()
	if b.CPUAcct {
		if cpuacctPath, err = CreateSubCGroupPath("cpuacct", b.Prefix); err != nil {
			return
		}
	}
	if b.Memory {
		if memoryPath, err = CreateSubCGroupPath("memory", b.Prefix); err != nil {
			return
		}
	}
	if b.Pids {
		if pidsPath, err = CreateSubCGroupPath("pids", b.Prefix); err != nil {
			return
		}
	}

	return &CGroup{
		prefix:  b.Prefix,
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

// Destroy removes dir for sub-cggroup, errors are ignored if remove one failed
func (c *CGroup) Destroy() error {
	var err1 error
	if err := remove(c.cpuacct.path); err != nil {
		err1 = err
	}
	if err := remove(c.memory.path); err != nil {
		err1 = err
	}
	if err := remove(c.pids.path); err != nil {
		err1 = err
	}
	return err1
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

func remove(name string) error {
	if name != "" {
		return os.Remove(name)
	}
	return nil
}
