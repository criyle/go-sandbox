package cgroup

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// Cgroup is the combination of sub-cgroups
type Cgroup struct {
	prefix string

	cpuset  *SubCgroup
	cpuacct *SubCgroup
	memory  *SubCgroup
	pids    *SubCgroup
}

// Build creates new cgrouup directories
func (b *Builder) Build() (cg *Cgroup, err error) {
	var (
		cpuSetPath, cpuacctPath, memoryPath, pidsPath string
	)
	// if failed, remove potential created directory
	defer func() {
		if err != nil {
			remove(cpuSetPath)
			remove(cpuacctPath)
			remove(memoryPath)
			remove(pidsPath)
		}
	}()
	for _, c := range []struct {
		enable bool
		name   string
		path   *string
	}{
		{b.CPUSet, "cpuset", &cpuSetPath},
		{b.CPUAcct, "cpuacct", &cpuacctPath},
		{b.Memory, "memory", &memoryPath},
		{b.Pids, "pids", &pidsPath},
	} {
		if !c.enable {
			continue
		}
		if *c.path, err = CreateSubCgroupPath(c.name, b.Prefix); err != nil {
			return
		}
	}

	if b.CPUSet {
		if err = initCpuset(cpuSetPath); err != nil {
			return
		}
	}

	return &Cgroup{
		prefix:  b.Prefix,
		cpuset:  NewSubCgroup(cpuSetPath),
		cpuacct: NewSubCgroup(cpuacctPath),
		memory:  NewSubCgroup(memoryPath),
		pids:    NewSubCgroup(pidsPath),
	}, nil
}

// AddProc writes cgroup.procs to all sub-cgroup
func (c *Cgroup) AddProc(pid int) error {
	for _, s := range []*SubCgroup{c.cpuset, c.cpuset, c.memory, c.pids} {
		if err := s.WriteUint(cgroupProcs, uint64(pid)); err != nil {
			return err
		}
	}
	return nil
}

// Destroy removes dir for sub-cgroup, errors are ignored if remove one failed
func (c *Cgroup) Destroy() error {
	var err1 error
	for _, s := range []*SubCgroup{c.cpuset, c.cpuset, c.memory, c.pids} {
		if err := remove(s.path); err != nil {
			err1 = err
		}
	}
	return err1
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
	if len(strings.TrimSpace(string(b))) > 0 {
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
