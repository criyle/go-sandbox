package cgroup

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
)

const numberOfControllers = 5

type Controllers struct {
	CPU     bool
	CPUSet  bool
	CPUAcct bool
	Memory  bool
	Pids    bool
}

func (c *Controllers) Set(ct string, value bool) {
	switch ct {
	case CPU:
		c.CPU = value
	case CPUSet:
		c.CPUSet = value
	case CPUAcct:
		c.CPUAcct = value
	case Memory:
		c.Memory = value
	case Pids:
		c.Pids = value
	}
}

func (c *Controllers) Intersect(o *Controllers) {
	c.CPU = c.CPU && o.CPU
	c.CPUSet = c.CPUSet && o.CPUSet
	c.CPUAcct = c.CPUAcct && o.CPUAcct
	c.Memory = c.Memory && o.Memory
	c.Pids = c.Pids && o.Pids
}

// Contains returns true if the current controller enabled all controllers in the other controller
func (c *Controllers) Contains(o *Controllers) bool {
	return (c.CPU || !o.CPU) && (c.CPUSet || !o.CPUSet) && (c.CPUAcct || !o.CPUAcct) &&
		(c.Memory || !o.Memory) && (c.Pids || !o.Pids)
}

func (c *Controllers) Names() []string {
	names := make([]string, 0, numberOfControllers)
	for _, v := range []struct {
		e bool
		n string
	}{
		{c.CPU, CPU},
		{c.CPUAcct, CPUAcct},
		{c.CPUSet, CPUSet},
		{c.Memory, Memory},
		{c.Pids, Pids},
	} {
		if v.e {
			names = append(names, v.n)
		}
	}
	return names
}

func (c *Controllers) String() string {
	return "[" + strings.Join(c.Names(), ", ") + "]"
}

// Info reads the cgroup mount info from /proc/cgroups
type Info struct {
	Hierarchy  int
	NumCgroups int
	Enabled    bool
}

// GetCgroupV1Info read /proc/cgroups and return the result
func GetCgroupV1Info() (map[string]Info, error) {
	f, err := os.Open(procCgroupsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rt := make(map[string]Info)
	s := bufio.NewScanner(f)
	for s.Scan() {
		text := s.Text()
		if text[0] == '#' {
			continue
		}
		parts := strings.Fields(text)
		if len(parts) < 4 {
			continue
		}

		// format: subsys_name hierarchy num_cgroups enabled
		name := parts[0]
		hierarchy, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, err
		}
		numCgroups, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil, err
		}
		enabled := parts[3] != "0"
		rt[name] = Info{
			Hierarchy:  hierarchy,
			NumCgroups: numCgroups,
			Enabled:    enabled,
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return rt, nil
}

func GetCurrentCgroupPrefix() (string, error) {
	c, err := os.ReadFile(procSelfCgroup)
	if err != nil {
		return "", err
	}
	firstLine, _, _ := strings.Cut(string(c), "\n")
	f := strings.Split(firstLine, ":")
	if len(f) < 3 {
		return "", fmt.Errorf("invalid " + procSelfCgroup)
	}
	return f[2][1:], nil
}

func GetAvailableController() (*Controllers, error) {
	if DetectedCgroupType == CgroupTypeV1 {
		return GetAvailableControllerV1()
	}
	return GetAvailableControllerV2()
}

func GetAvailableControllerWithPrefix(prefix string) (*Controllers, error) {
	if DetectedCgroupType == CgroupTypeV1 {
		return GetAvailableControllerV1()
	}
	return getAvailableControllerV2(prefix)
}

// GetAvailableControllerV1 reads /proc/cgroups and get all available controller as set
func GetAvailableControllerV1() (*Controllers, error) {
	info, err := GetCgroupV1Info()
	if err != nil {
		return nil, err
	}

	rt := &Controllers{}
	for k, v := range info {
		if !v.Enabled {
			continue
		}
		rt.Set(k, true)
	}
	return rt, nil
}

// GetAvailableControllerV2 reads /sys/fs/cgroup/cgroup.controllers to get all controller
func GetAvailableControllerV2() (*Controllers, error) {
	return getAvailableControllerV2(".")
}

func getAvailableControllerV2(prefix string) (*Controllers, error) {
	return getAvailableControllerV2path(path.Join(basePath, prefix, cgroupControllers))
}

func getAvailableControllerV2path(p string) (*Controllers, error) {
	c, err := readFile(p)
	if err != nil {
		return nil, err
	}

	m := &Controllers{}
	f := strings.Fields(string(c))
	for _, v := range f {
		m.Set(v, true)
	}
	return m, nil
}
