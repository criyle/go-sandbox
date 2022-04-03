package cgroup

import (
	"bufio"
	"os"
	"path"
	"strconv"
	"strings"
)

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

// GetAvailableControllerV1 reads /proc/cgroups and get all available controller as set
func GetAvailableControllerV1() (map[string]bool, error) {
	info, err := GetCgroupV1Info()
	if err != nil {
		return nil, err
	}

	rt := make(map[string]bool)
	for k, v := range info {
		if !v.Enabled {
			continue
		}
		rt[k] = true
	}
	return rt, nil
}

// GetAvailableControllerV2 reads /sys/fs/cgroup/cgroup.controllers to get all controller
func GetAvailableControllerV2() (map[string]bool, error) {
	c, err := readFile(path.Join(basePath, cgroupControllers))
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool)
	f := strings.Fields(string(c))
	for _, v := range f {
		m[v] = true
	}
	return m, nil
}
