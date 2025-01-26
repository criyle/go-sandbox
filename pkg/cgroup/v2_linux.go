package cgroup

import (
	"bufio"
	"bytes"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
)

// V2 provides cgroup interface for v2
type V2 struct {
	path        string
	control     *Controllers
	subtreeOnce sync.Once
	subtreeErr  error
	existing    bool
}

var _ Cgroup = &V2{}

func (c *V2) String() string {
	ct, _ := getAvailableControllerV2path(path.Join(c.path, cgroupControllers))
	return "v2(" + c.path + ")" + ct.String()
}

// AddProc adds processes into the cgroup
func (c *V2) AddProc(pids ...int) error {
	return AddProcesses(path.Join(c.path, cgroupProcs), pids)
}

// Processes returns all processes within the cgroup
func (c *V2) Processes() ([]int, error) {
	return ReadProcesses(path.Join(c.path, cgroupProcs))
}

// New creates a sub-cgroup based on the existing one
func (c *V2) New(name string) (Cgroup, error) {
	if err := c.enableSubtreeControl(); err != nil {
		return nil, err
	}
	v2 := &V2{
		path:    path.Join(c.path, name),
		control: c.control,
	}
	if err := os.Mkdir(v2.path, dirPerm); err != nil {
		if !os.IsExist(err) {
			return nil, err
		}
		v2.existing = true
	}
	return v2, nil
}

// Nest creates a sub-cgroup, moves current process into that cgroup
func (c *V2) Nest(name string) (Cgroup, error) {
	v2 := &V2{
		path:    path.Join(c.path, name),
		control: c.control,
	}
	if err := os.Mkdir(v2.path, dirPerm); err != nil {
		if !os.IsExist(err) {
			return nil, err
		}
		v2.existing = true
	}
	p, err := c.Processes()
	if err != nil {
		return nil, err
	}
	if err := v2.AddProc(p...); err != nil {
		return nil, err
	}
	if err := c.enableSubtreeControl(); err != nil {
		return nil, err
	}
	return v2, nil
}

func (c *V2) enableSubtreeControl() error {
	c.subtreeOnce.Do(func() {
		ct, err := getAvailableControllerV2path(path.Join(c.path, cgroupControllers))
		if err != nil {
			c.subtreeErr = err
			return
		}
		ect, err := getAvailableControllerV2path(path.Join(c.path, cgroupSubtreeControl))
		if err != nil {
			c.subtreeErr = err
			return
		}
		if ect.Contains(ct) {
			return
		}
		s := ct.Names()
		controlMsg := []byte("+" + strings.Join(s, " +"))
		c.subtreeErr = writeFile(path.Join(c.path, cgroupSubtreeControl), controlMsg, filePerm)
	})
	return c.subtreeErr
}

// Random creates a sub-cgroup based on the existing one but the name is randomly generated
func (c *V2) Random(pattern string) (Cgroup, error) {
	return randomBuild(pattern, c.New)
}

// Destroy destroys the cgroup
func (c *V2) Destroy() error {
	if !c.existing {
		return remove(c.path)
	}
	return nil
}

// Existing returns true if the cgroup was opened rather than created
func (c *V2) Existing() bool {
	return c.existing
}

// CPUUsage reads cpu.stat usage_usec
func (c *V2) CPUUsage() (uint64, error) {
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
func (c *V2) MemoryUsage() (uint64, error) {
	if !c.control.Memory {
		return 0, ErrNotInitialized
	}
	return c.ReadUint("memory.current")
}

// MemoryMaxUsage reads memory.peak
func (c *V2) MemoryMaxUsage() (uint64, error) {
	if !c.control.Memory {
		return 0, ErrNotInitialized
	}
	return c.ReadUint("memory.peak")
}

// SetCPUBandwidth set cpu.max quota period
func (c *V2) SetCPUBandwidth(quota, period uint64) error {
	if !c.control.CPU {
		return ErrNotInitialized
	}
	content := strconv.FormatUint(quota, 10) + " " + strconv.FormatUint(period, 10)
	return c.WriteFile("cpu.max", []byte(content))
}

// SetCPUSet sets cpuset.cpus
func (c *V2) SetCPUSet(content []byte) error {
	if !c.control.CPUSet {
		return ErrNotInitialized
	}
	return c.WriteFile("cpuset.cpus", content)
}

// SetMemoryLimit memory.max
func (c *V2) SetMemoryLimit(l uint64) error {
	if !c.control.Memory {
		return ErrNotInitialized
	}
	return c.WriteUint("memory.max", l)
}

// SetProcLimit pids.max
func (c *V2) SetProcLimit(l uint64) error {
	if !c.control.Pids {
		return ErrNotInitialized
	}
	return c.WriteUint("pids.max", l)
}

// WriteUint writes uint64 into given file
func (c *V2) WriteUint(filename string, i uint64) error {
	return c.WriteFile(filename, []byte(strconv.FormatUint(i, 10)))
}

// ReadUint read uint64 from given file
func (c *V2) ReadUint(filename string) (uint64, error) {
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
func (c *V2) WriteFile(name string, content []byte) error {
	p := path.Join(c.path, name)
	return writeFile(p, content, filePerm)
}

// ReadFile reads cgroup file and handles potential EINTR error while read to
// the slow device (cgroup)
func (c *V2) ReadFile(name string) ([]byte, error) {
	p := path.Join(c.path, name)
	return readFile(p)
}
