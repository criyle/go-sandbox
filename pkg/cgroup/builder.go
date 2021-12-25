package cgroup

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
)

// Builder builds cgroup directories
// available: cpuacct, memory, pids
type Builder struct {
	Prefix string
	Type   CgroupType

	v2initOnce sync.Once
	v2initErr  error

	CPU     bool
	CPUSet  bool
	CPUAcct bool
	Memory  bool
	Pids    bool
}

type CgroupType int

const (
	CgroupTypeV1 = iota + 1
	CgroupTypeV2
)

func (t CgroupType) String() string {
	switch t {
	case CgroupTypeV1:
		return "v1"
	case CgroupTypeV2:
		return "v2"
	default:
		return "invalid"
	}
}

// NewBuilder return a dumb builder without any controller
func NewBuilder(prefix string) *Builder {
	return &Builder{
		Prefix: prefix,
		Type:   CgroupTypeV1,
	}
}

func (b *Builder) WithType(t CgroupType) *Builder {
	b.Type = t
	return b
}

// WithCPU includes cpu cgroup
func (b *Builder) WithCPU() *Builder {
	b.CPU = true
	return b
}

// WithCPUSet includes cpuset cgroup
func (b *Builder) WithCPUSet() *Builder {
	b.CPUSet = true
	return b
}

// WithCPUAcct includes cpuacct cgroup
func (b *Builder) WithCPUAcct() *Builder {
	b.CPUAcct = true
	return b
}

// WithMemory includes memory cgroup
func (b *Builder) WithMemory() *Builder {
	b.Memory = true
	return b
}

// WithPids includes pids cgroup
func (b *Builder) WithPids() *Builder {
	b.Pids = true
	return b
}

// FilterByEnv reads /proc/cgroups and filter out non-exists ones
func (b *Builder) FilterByEnv() (*Builder, error) {
	m, err := b.getAvailableController()
	if err != nil {
		return b, err
	}
	b.CPU = b.CPU && m["cpu"]
	b.CPUSet = b.CPUSet && m["cpuset"]
	b.CPUAcct = b.CPUAcct && m["cpuacct"]
	b.Memory = b.Memory && m["memory"]
	b.Pids = b.Pids && m["pids"]
	return b, nil
}

func (b *Builder) getAvailableController() (map[string]bool, error) {
	switch b.Type {
	case CgroupTypeV1:
		return GetAvailableControllerV1()
	case CgroupTypeV2:
		return GetAvailableControllerV2()
	}
	return nil, os.ErrInvalid
}

func (b *Builder) loopControllerNames(f func(name string)) {
	for _, t := range []struct {
		name    string
		enabled bool
	}{
		{"cpu", b.CPU},
		{"cpuset", b.CPUSet},
		{"cpuacct", b.CPUAcct},
		{"memory", b.Memory},
		{"pids", b.Pids},
	} {
		if t.enabled {
			f(t.name)
		}
	}
}

func (b *Builder) controllerNames() []string {
	s := make([]string, 0, 5)
	b.loopControllerNames(func(name string) {
		s = append(s, name)
	})
	return s
}

// String prints the build properties
func (b *Builder) String() string {
	s := b.controllerNames()
	return fmt.Sprintf("cgroup builder(%v): [%s]", b.Type, strings.Join(s, ", "))
}

// Build creates new cgrouup directories
func (b *Builder) Build(name string) (Cgroup, error) {
	if b.Type == CgroupTypeV1 {
		return b.buildV1(name)
	}
	return b.buildV2(name)
}

func nextRandom() string {
	return strconv.Itoa(int(rand.Int31()))
}

// Random creates a cgroup with random directory, similar to os.MkdirTemp
func (b *Builder) Random(pattern string) (Cgroup, error) {
	prefix, suffix, err := prefixAndSuffix(pattern)
	if err != nil {
		return nil, fmt.Errorf("cgroup.builder: random %v", err)
	}

	try := 0
	for {
		name := prefix + nextRandom() + suffix
		cg, err := b.Build(name)
		if err == nil {
			return cg, nil
		}
		if errors.Is(err, os.ErrExist) {
			if try++; try < 10000 {
				continue
			}
			return nil, fmt.Errorf("cgroup.builder: tried 10000 times but failed")
		}
		return nil, fmt.Errorf("cgroup.builder: random %v", err)
	}
}

func (b *Builder) buildV2(name string) (cg Cgroup, err error) {
	// make prefix if not exist
	if err := b.ensurePrefixV2Once(); err != nil {
		return nil, err
	}

	p := path.Join(basePath, b.Prefix, name)
	defer func() {
		if err != nil {
			remove(p)
		}
	}()

	// make dir
	if err := os.Mkdir(p, dirPerm); err != nil {
		return nil, err
	}
	return &CgroupV2{p}, nil
}

func (b *Builder) ensurePrefixV2Once() error {
	b.v2initOnce.Do(func() {
		b.v2initErr = b.ensurePrefixV2()
	})
	return b.v2initErr
}

func (b *Builder) ensurePrefixV2() error {
	s := b.controllerNames()
	controlMsg := []byte("+" + strings.Join(s, " +"))

	// start from base dir
	entries := strings.Split(b.Prefix, "/")
	current := basePath
	for _, e := range entries {
		current += "/" + e
		if err := os.Mkdir(current, dirPerm); err == nil {
			if err := writeFile(path.Join(current, cgroupSubtreeControl), controlMsg, filePerm); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *Builder) buildV1(name string) (cg Cgroup, err error) {
	v1 := &CgroupV1{prefix: b.Prefix}

	// if failed, remove potential created directory
	defer func() {
		if err != nil {
			for _, p := range v1.all {
				remove(p.path)
			}
		}
	}()

	for _, c := range []struct {
		enable bool
		name   string
		cg     **v1controller
	}{
		{b.CPU, "cpu", &v1.cpu},
		{b.CPUSet, "cpuset", &v1.cpuset},
		{b.CPUAcct, "cpuacct", &v1.cpuacct},
		{b.Memory, "memory", &v1.memory},
		{b.Pids, "pids", &v1.pids},
	} {
		if !c.enable {
			continue
		}

		var path string
		path, err = CreateV1ControllerPathName(c.name, b.Prefix, name)
		*c.cg = NewV1Controller(path)
		if errors.Is(err, os.ErrExist) {
			// do not ignore first time error, which means collapse
			if len(v1.all) == 0 {
				return
			}
			err = nil
			continue
		}
		if err != nil {
			return
		}
		v1.all = append(v1.all, *c.cg)
	}

	// init cpu set before use, otherwise it is not functional
	if v1.cpuset != nil {
		if err = initCpuset(v1.cpuset.path); err != nil {
			return
		}
	}

	return v1, nil
}
