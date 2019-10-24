package cgroup

import (
	"fmt"
	"strings"
)

// Builder builds cgroup directories
// avaliable: cpuacct, memory, pids
type Builder struct {
	Prefix                string
	CPUAcct, Memory, Pids bool
}

// NewBuilder return a dumb builder without any sub-cgroup
func NewBuilder(prefix string) *Builder {
	return &Builder{
		Prefix: prefix,
	}
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
	m, err := GetAllSubCgroup()
	if err != nil {
		return b, err
	}
	b.CPUAcct = b.CPUAcct && m["cpuacct"]
	b.Memory = b.Memory && m["memory"]
	b.Pids = b.Pids && m["pids"]
	return b, nil
}

// String prints the build properties
func (b *Builder) String() string {
	s := make([]string, 0, 3)
	for _, t := range []struct {
		name    string
		enabled bool
	}{
		{"cpuacct", b.CPUAcct},
		{"memory", b.Memory},
		{"pids", b.Pids},
	} {
		if t.enabled {
			s = append(s, t.name)
		}
	}
	return fmt.Sprintf("cgroup builder: [%s]", strings.Join(s, ", "))
}
