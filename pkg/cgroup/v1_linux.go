package cgroup

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
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

	existing bool
}

func (c *CgroupV1) String() string {
	names := make([]string, 0, numberOfControllers)
	for _, v := range []struct {
		now  *v1controller
		name string
	}{
		{c.cpu, CPU},
		{c.cpuset, CPUSet},
		{c.cpuacct, CPUAcct},
		{c.memory, Memory},
		{c.pids, Pids},
	} {
		if v.now == nil {
			continue
		}
		names = append(names, v.name)
	}
	return "v1(" + c.prefix + ")[" + strings.Join(names, ", ") + "]"
}

// AddProc writes cgroup.procs to all controller
func (c *CgroupV1) AddProc(pids ...int) error {
	for _, s := range c.all {
		if err := s.AddProc(pids...); err != nil {
			return err
		}
	}
	return nil
}

// Processes lists all existing process pid from the cgroup
func (c *CgroupV1) Processes() ([]int, error) {
	if len(c.all) == 0 {
		return nil, os.ErrInvalid
	}
	return ReadProcesses(path.Join(c.all[0].path, cgroupProcs))
}

// New creates a sub-cgroup based on the existing one
func (c *CgroupV1) New(name string) (cg Cgroup, err error) {
	v1 := &CgroupV1{
		prefix: path.Join(c.prefix, name),
	}
	defer func() {
		if err != nil {
			for _, v := range v1.all {
				remove(v.path)
			}
		}
	}()
	for _, v := range []struct {
		now *v1controller
		new **v1controller
	}{
		{c.cpu, &v1.cpu},
		{c.cpuset, &v1.cpuset},
		{c.cpuacct, &v1.cpuacct},
		{c.memory, &v1.memory},
		{c.pids, &v1.pids},
	} {
		if v.now == nil {
			continue
		}
		p := path.Join(v.now.path, name)
		*v.new = &v1controller{path: p}
		err = EnsureDirExists(p)
		if os.IsExist(err) {
			err = nil
			if len(v1.all) == 0 {
				v1.existing = true
			}
			continue
		}
		if err != nil {
			return
		}
		v1.all = append(v1.all, *v.new)
	}
	// init cpu set before use, otherwise it is not functional
	if v1.cpuset != nil {
		if err = initCpuset(v1.cpuset.path); err != nil {
			return
		}
	}
	return v1, nil
}

// Random creates a sub-cgroup based on the existing one but the name is randomly generated
func (c *CgroupV1) Random(pattern string) (Cgroup, error) {
	return randomBuild(pattern, c.New)
}

// Nest creates a sub-cgroup, moves current process into that cgroup
func (c *CgroupV1) Nest(name string) (Cgroup, error) {
	v1, err := c.New(name)
	if err != nil {
		return nil, err
	}
	p, err := c.Processes()
	if err != nil {
		return nil, err
	}
	if err := v1.AddProc(p...); err != nil {
		return nil, err
	}
	return v1, nil
}

// Destroy removes dir for controllers recursively, errors are ignored if remove one failed
func (c *CgroupV1) Destroy() error {
	var err1 error
	for _, s := range c.all {
		if c.existing {
			continue
		}
		if err := remove(s.path); err != nil {
			err1 = err
		}
	}
	return err1
}

// Existing returns true if the cgroup was opened rather than created
func (c *CgroupV1) Existing() bool {
	return c.existing
}

func (c *CgroupV1) SetCPUBandwidth(quota, period uint64) error {
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
	// otherwise copy from parent, first to ensure it is empty by recursion
	if err := copyCgroupPropertyFromParent(filepath.Dir(path), name); err != nil {
		return err
	}
	b, err = os.ReadFile(filepath.Join(filepath.Dir(path), name))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(path, name), b, filePerm)
}
