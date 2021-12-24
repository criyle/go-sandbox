package cgroup

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

var _ Cgroup = &CgroupV1{}

// CgroupV1 is the combination of v1 controllers
type CgroupV1 struct {
	prefix string

	cpu     *v1controller
	cpuset  *v1controller
	cpuacct *v1controller
	memory  *v1controller
	pids    *v1controller

	all []*v1controller
}

// AddProc writes cgroup.procs to all controller
func (c *CgroupV1) AddProc(pid int) error {
	for _, s := range c.all {
		if err := s.WriteUint(cgroupProcs, uint64(pid)); err != nil {
			return err
		}
	}
	return nil
}

// Destroy removes dir for controller, errors are ignored if remove one failed
func (c *CgroupV1) Destroy() error {
	var err1 error
	for _, s := range c.all {
		if err := remove(s.path); err != nil {
			err1 = err
		}
	}
	return err1
}

func (c *CgroupV1) SetCPUBandwidth(period, quota uint64) error {
	if err := c.SetCPUCfsQuota(quota); err != nil {
		return err
	}
	return c.SetCPUCfsPeriod(period)
}

// SetCPUSet set cpuset.cpus
func (c *CgroupV1) SetCPUSet(b []byte) error {
	return c.cpuset.WriteFile("cpuset.cpus", b)
}

// CpuacctUsage read cpuacct.usage in ns
func (c *CgroupV1) CPUUsage() (uint64, error) {
	return c.cpuacct.ReadUint("cpuacct.usage")
}

// MemoryUsage read memory.usage_in_bytes
func (c *CgroupV1) MemoryUsage() (uint64, error) {
	return c.memory.ReadUint("memory.usage_in_bytes")
}

// MemoryMaxUsage read memory.max_usage_in_bytes
func (c *CgroupV1) MemoryMaxUsage() (uint64, error) {
	return c.memory.ReadUint("memory.max_usage_in_bytes")
}

// SetMemoryLimit write memory.limit_in_bytes
func (c *CgroupV1) SetMemoryLimit(i uint64) error {
	return c.memory.WriteUint("memory.limit_in_bytes", i)
}

// SetProcLimit write pids.max
func (c *CgroupV1) SetProcLimit(i uint64) error {
	return c.pids.WriteUint("pids.max", i)
}

// SetCpuacctUsage write cpuacct.usage in ns
func (c *CgroupV1) SetCpuacctUsage(i uint64) error {
	return c.cpuacct.WriteUint("cpuacct.usage", i)
}

// SetMemoryMaxUsageInBytes write cpuacct.usage in ns
func (c *CgroupV1) SetMemoryMaxUsageInBytes(i uint64) error {
	return c.memory.WriteUint("memory.max_usage_in_bytes", i)
}

// MemoryMemswMaxUsageInBytes read memory.memsw.max_usage_in_bytes
func (c *CgroupV1) MemoryMemswMaxUsageInBytes() (uint64, error) {
	return c.memory.ReadUint("memory.memsw.max_usage_in_bytes")
}

// SetMemoryMemswLimitInBytes write memory.memsw.limit_in_bytes
func (c *CgroupV1) SetMemoryMemswLimitInBytes(i uint64) error {
	return c.memory.WriteUint("memory.memsw.limit_in_bytes", i)
}

// SetCPUCfsPeriod set cpu.cfs_period_us in us
func (c *CgroupV1) SetCPUCfsPeriod(p uint64) error {
	return c.cpu.WriteUint("cpu.cfs_period_us", p)
}

// SetCPUCfsQuota set cpu.cfs_quota_us in us
func (c *CgroupV1) SetCPUCfsQuota(p uint64) error {
	return c.cpu.WriteUint("cpu.cfs_quota_us", p)
}

// SetCpusetMems set cpuset.mems
func (c *CgroupV1) SetCpusetMems(b []byte) error {
	return c.cpuset.WriteFile("cpuset.mems", b)
}

// FindMemoryStatProperty find certain property from memory.stat
func (c *CgroupV1) FindMemoryStatProperty(prop string) (uint64, error) {
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

// initCpuset will copy the config from the parent cpu sets if not exists
func initCpuset(path string) error {
	for _, f := range []string{"cpuset.cpus", "cpuset.mems"} {
		if err := copyCgroupPropertyFromParent(path, f); err != nil {
			return err
		}
	}
	return nil
}

func copyCgroupPropertyFromParent(path, name string) error {
	// ensure current one empty
	b, err := os.ReadFile(filepath.Join(path, name))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(b)) > 0 {
		return nil
	}
	// otherwise copy from parent, first to ensure it is empty by recurssion
	if err := copyCgroupPropertyFromParent(filepath.Dir(path), name); err != nil {
		return err
	}
	b, err = os.ReadFile(filepath.Join(filepath.Dir(path), name))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(path, name), b, filePerm)
}
