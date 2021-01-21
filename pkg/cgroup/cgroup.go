package cgroup

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Cgroup is the combination of sub-cgroups
type Cgroup struct {
	prefix string

	cpu     *SubCgroup
	cpuset  *SubCgroup
	cpuacct *SubCgroup
	memory  *SubCgroup
	pids    *SubCgroup

	all []*SubCgroup
}

// Build creates new cgrouup directories
func (b *Builder) Build() (cg *Cgroup, err error) {
	var (
		paths     []string
		subCgroup = make(map[int]*SubCgroup)
		info      = getCachedCgroupHierarchy()
	)
	// if failed, remove potential created directory
	defer func() {
		if err != nil {
			removeAll(paths...)
		}
	}()
	for _, c := range []struct {
		enable bool
		name   string
	}{
		{b.CPU, "cpu"},
		{b.CPUSet, "cpuset"},
		{b.CPUAcct, "cpuacct"},
		{b.Memory, "memory"},
		{b.Pids, "pids"},
	} {
		if !c.enable {
			continue
		}
		h := info[c.name]
		if subCgroup[h] == nil {
			var path string
			if path, err = CreateSubCgroupPath(c.name, b.Prefix); err != nil {
				return
			}
			paths = append(paths, path)
			subCgroup[h] = NewSubCgroup(path)
		}
	}

	if b.CPUSet {
		if err = initCpuset(subCgroup[info["cpuset"]].path); err != nil {
			return
		}
	}

	var all []*SubCgroup
	for _, v := range subCgroup {
		all = append(all, v)
	}

	return &Cgroup{
		prefix:  b.Prefix,
		cpu:     subCgroup[info["cpu"]],
		cpuset:  subCgroup[info["cpuset"]],
		cpuacct: subCgroup[info["cpuacct"]],
		memory:  subCgroup[info["memory"]],
		pids:    subCgroup[info["pids"]],
		all:     all,
	}, nil
}

// AddProc writes cgroup.procs to all sub-cgroup
func (c *Cgroup) AddProc(pid int) error {
	for _, s := range c.all {
		if err := s.WriteUint(cgroupProcs, uint64(pid)); err != nil {
			return err
		}
	}
	return nil
}

// Destroy removes dir for sub-cgroup, errors are ignored if remove one failed
func (c *Cgroup) Destroy() error {
	var err1 error
	for _, s := range c.all {
		if err := remove(s.path); err != nil {
			err1 = err
		}
	}
	return err1
}

// SetCPUCfsPeriod set cpu.cfs_period_us in us
func (c *Cgroup) SetCPUCfsPeriod(p uint64) error {
	return c.cpu.WriteUint("cpu.cfs_period_us", p)
}

// SetCPUCfsQuota set cpu.cfs_quota_us in us
func (c *Cgroup) SetCPUCfsQuota(p uint64) error {
	return c.cpu.WriteUint("cpu.cfs_quota_us", p)
}

// SetCpusetCpus set cpuset.cpus
func (c *Cgroup) SetCpusetCpus(b []byte) error {
	return c.cpuset.WriteFile("cpuset.cpus", b)
}

// SetCpusetMems set cpuset.mems
func (c *Cgroup) SetCpusetMems(b []byte) error {
	return c.cpuset.WriteFile("cpuset.mems", b)
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

// MemoryMemswMaxUsageInBytes read memory.memsw.max_usage_in_bytes
func (c *Cgroup) MemoryMemswMaxUsageInBytes() (uint64, error) {
	return c.memory.ReadUint("memory.memsw.max_usage_in_bytes")
}

// SetMemoryMemswLimitInBytes write memory.memsw.limit_in_bytes
func (c *Cgroup) SetMemoryMemswLimitInBytes(i uint64) error {
	return c.memory.WriteUint("memory.memsw.limit_in_bytes", i)
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
	b, err := ioutil.ReadFile(filepath.Join(path, name))
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
	b, err = ioutil.ReadFile(filepath.Join(filepath.Dir(path), name))
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(path, name), b, filePerm)
}

func remove(name string) error {
	if name != "" {
		return os.Remove(name)
	}
	return nil
}

func removeAll(name ...string) error {
	var err1 error
	for _, n := range name {
		err := remove(n)
		if err != nil && err1 == nil {
			err1 = err
		}
	}
	return err1
}
