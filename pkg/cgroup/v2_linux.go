package cgroup

import (
	"bufio"
	"bytes"
	"os"
	"path"
	"strconv"
	"strings"
)

type CgroupV2 struct {
	path string
}

var _ Cgroup = &CgroupV2{}

func (c *CgroupV2) AddProc(pid int) error {
	return c.WriteUint(cgroupProcs, uint64(pid))
}

func (c *CgroupV2) Destroy() error {
	return remove(c.path)
}

// CPUUsage reads cpu.stat usage_usec
func (c *CgroupV2) CPUUsage() (uint64, error) {
	b, err := c.ReadFile("cpu.stat")
	if err != nil {
		return 0, err
	}
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		parts := strings.Fields(s.Text())
		if len(parts) == 2 && parts[0] == "usage_usec" {
			v, err := strconv.Atoi(parts[1])
			if err != nil {
				return 0, err
			}
			return uint64(v) * 1000, nil // to ns
		}
	}
	return 0, os.ErrNotExist
}

// MemoryUsage reads memory.current
func (c *CgroupV2) MemoryUsage() (uint64, error) {
	return c.ReadUint("memory.current")
}

// MemoryMaxUsage reads memory.peak
func (c *CgroupV2) MemoryMaxUsage() (uint64, error) {
	return c.ReadUint("memory.peak")
}

// SetCPUBandwidth set cpu.max quota period
func (c *CgroupV2) SetCPUBandwidth(quota, period uint64) error {
	content := strconv.FormatUint(quota, 10) + " " + strconv.FormatUint(period, 10)
	return c.WriteFile("cpu.max", []byte(content))
}

// SetCPUSet sets cpuset.cpus
func (c *CgroupV2) SetCPUSet(content []byte) error {
	return c.WriteFile("cpuset.cpus", content)
}

// SetMemoryLimit memory.max
func (c *CgroupV2) SetMemoryLimit(l uint64) error {
	return c.WriteUint("memory.max", l)
}

// SetProcLimit pids.max
func (c *CgroupV2) SetProcLimit(l uint64) error {
	return c.WriteUint("pids.max", l)
}

// WriteUint writes uint64 into given file
func (c *CgroupV2) WriteUint(filename string, i uint64) error {
	return c.WriteFile(filename, []byte(strconv.FormatUint(i, 10)))
}

// ReadUint read uint64 from given file
func (c *CgroupV2) ReadUint(filename string) (uint64, error) {
	b, err := c.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	s, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, err
	}
	return s, nil
}

// WriteFile writes cgroup file and handles potential EINTR error while writes to
// the slow device (cgroup)
func (c *CgroupV2) WriteFile(name string, content []byte) error {
	p := path.Join(c.path, name)
	return writeFile(p, content, filePerm)
}

// ReadFile reads cgroup file and handles potential EINTR error while read to
// the slow device (cgroup)
func (c *CgroupV2) ReadFile(name string) ([]byte, error) {
	p := path.Join(c.path, name)
	return readFile(p)
}
