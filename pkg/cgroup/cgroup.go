package cgroup

import (
	"bytes"
	"fmt"
	"os"
)

// Cgroup is the combination of sub-cgroups
type Cgroup struct {
	prefix                string
	cpuacct, memory, pids *SubCgroup
}

// Build creates new cgrouup directories
func (b *Builder) Build() (cg *Cgroup, err error) {
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
		if cpuacctPath, err = CreateSubCgroupPath("cpuacct", b.Prefix); err != nil {
			return
		}
	}
	if b.Memory {
		if memoryPath, err = CreateSubCgroupPath("memory", b.Prefix); err != nil {
			return
		}
	}
	if b.Pids {
		if pidsPath, err = CreateSubCgroupPath("pids", b.Prefix); err != nil {
			return
		}
	}

	return &Cgroup{
		prefix:  b.Prefix,
		cpuacct: NewSubCgroup(cpuacctPath),
		memory:  NewSubCgroup(memoryPath),
		pids:    NewSubCgroup(pidsPath),
	}, nil
}

// AddProc writes cgroup.procs to all sub-cgroup
func (c *Cgroup) AddProc(pid int) error {
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

// Destroy removes dir for sub-cgroup, errors are ignored if remove one failed
func (c *Cgroup) Destroy() error {
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
func (c *Cgroup) CpuacctUsage() (uint64, error) {
	return c.cpuacct.ReadUint("cpuacct.usage")
}

// MemoryMaxUsageInBytes read memory.max_usage_in_bytes
func (c *Cgroup) MemoryMaxUsageInBytes() (uint64, error) {
	return c.memory.ReadUint("memory.max_usage_in_bytes")
}

// SetMemoryLimitInBytes write memory.limit_in_bytes
func (c *Cgroup) SetMemoryLimitInBytes(i uint64) error {
	return c.memory.WriteUint("memory.limit_in_bytes", i)
}

// SetPidsMax write pids.max
func (c *Cgroup) SetPidsMax(i uint64) error {
	return c.pids.WriteUint("pids.max", i)
}

// SetCpuacctUsage write cpuacct.usage in ns
func (c *Cgroup) SetCpuacctUsage(i uint64) error {
	return c.cpuacct.WriteUint("cpuacct.usage", i)
}

// SetMemoryMaxUsageInBytes write cpuacct.usage in ns
func (c *Cgroup) SetMemoryMaxUsageInBytes(i uint64) error {
	return c.memory.WriteUint("memory.max_usage_in_bytes", i)
}

// FindMemoryStatProperty find certain property from memory.stat
func (c *Cgroup) FindMemoryStatProperty(prop string) (uint64, error) {
	content, err := c.memory.ReadFile("memory.stat")
	if err != nil {
		return 0, err
	}
	r := bytes.NewReader(content)
	for {
		var p string
		var i uint64
		_, err = fmt.Fscanln(r, &p, &i)
		if err != nil {
			return 0, err
		}
		if p == prop {
			return i, nil
		}
	}
}

func remove(name string) error {
	if name != "" {
		return os.Remove(name)
	}
	return nil
}
