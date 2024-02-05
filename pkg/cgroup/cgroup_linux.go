package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
)

// Cgroup defines the common interface to control cgroups
// including v1 and v2 implementations.
// TODO: implement systemd integration
type Cgroup interface {
	// AddProc add a process into the cgroup
	AddProc(pid ...int) error

	// Destroy deletes the cgroup
	Destroy() error

	// Existing returns true if the cgroup was opened rather than created
	Existing() bool

	//Nest creates a sub-cgroup, moves current process into that cgroup
	Nest(name string) (Cgroup, error)

	// CPUUsage reads total cpu usage of cgroup
	CPUUsage() (uint64, error)

	// MemoryUsage reads current total memory usage
	MemoryUsage() (uint64, error)

	// MemoryMaxUsageInBytes reads max total memory usage. Not exist in cgroup v2 with kernel version < 5.19
	MemoryMaxUsage() (uint64, error)

	// SetCPUBandwidth sets the cpu bandwidth. Times in ns
	SetCPUBandwidth(quota, period uint64) error

	// SetCpusetCpus sets the available cpu to use (cpuset.cpus).
	SetCPUSet([]byte) error

	// SetMemoryLimit sets memory.limit_in_bytes
	SetMemoryLimit(uint64) error

	// SetProcLimit sets pids.max
	SetProcLimit(uint64) error

	// Processes lists all existing process pid from the cgroup
	Processes() ([]int, error)

	// New creates a sub-cgroup based on the existing one
	New(string) (Cgroup, error)

	// Random creates a sub-cgroup based on the existing one but the name is randomly generated
	Random(string) (Cgroup, error)
}

// DetectedCgroupType defines the current cgroup type of the system
var DetectedCgroupType = DetectType()

// New creates a new cgroup with provided prefix, it opens existing one if existed
func New(prefix string, ct *Controllers) (Cgroup, error) {
	if DetectedCgroupType == TypeV1 {
		return newV1(prefix, ct)
	}
	return newV2(prefix, ct)
}

func loopV1Controllers(ct *Controllers, v1 *V1, f func(string, **v1controller) error) error {
	for _, c := range []struct {
		available bool
		name      string
		cg        **v1controller
	}{
		{ct.CPU, CPU, &v1.cpu},
		{ct.CPUSet, CPUSet, &v1.cpuset},
		{ct.CPUAcct, CPUAcct, &v1.cpuacct},
		{ct.Memory, Memory, &v1.memory},
		{ct.Pids, Pids, &v1.pids},
	} {
		if !c.available {
			continue
		}
		if err := f(c.name, c.cg); err != nil {
			return err
		}
	}
	return nil
}

func newV1(prefix string, ct *Controllers) (cg Cgroup, err error) {
	v1 := &V1{
		prefix: prefix,
	}
	// if failed, remove potential created directory
	defer func() {
		if err != nil && !v1.existing {
			for _, p := range v1.all {
				remove(p.path)
			}
		}
	}()

	if err = loopV1Controllers(ct, v1, func(name string, cg **v1controller) error {
		path, err := CreateV1ControllerPath(name, prefix)
		*cg = newV1Controller(path)
		if errors.Is(err, os.ErrExist) {
			if len(v1.all) == 0 {
				v1.existing = true
			}
			return nil
		}
		if err != nil {
			return err
		}
		v1.all = append(v1.all, *cg)
		return nil
	}); err != nil {
		return
	}

	// init cpu set before use, otherwise it is not functional
	if v1.cpuset != nil {
		if err = initCpuset(v1.cpuset.path); err != nil {
			return
		}
	}
	return v1, err
}

func newV2(prefix string, ct *Controllers) (cg Cgroup, err error) {
	v2 := &V2{
		path: path.Join(basePath, prefix),
	}
	if _, err := os.Stat(v2.path); err == nil {
		v2.existing = true
	}
	defer func() {
		if err != nil && !v2.existing {
			remove(v2.path)
		}
	}()

	// ensure controllers were enabled
	s := ct.Names()
	controlMsg := []byte("+" + strings.Join(s, " +"))

	// start from base dir
	entries := strings.Split(prefix, "/")
	current := ""
	for _, e := range entries {
		parent := current
		current = current + "/" + e
		// try mkdir if not exists
		if _, err := os.Stat(path.Join(basePath, current)); os.IsNotExist(err) {
			if err := os.Mkdir(path.Join(basePath, current), dirPerm); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}

		// no err means create success, need to enable it in its parent folder
		ect, err := getAvailableControllerV2(current)
		if err != nil {
			return nil, err
		}
		if ect.Contains(ct) {
			continue
		}
		if err := writeFile(path.Join(basePath, parent, cgroupSubtreeControl), controlMsg, filePerm); err != nil {
			return nil, err
		}
	}
	return v2, nil
}

// OpenExisting opens a existing cgroup with provided prefix
func OpenExisting(prefix string, ct *Controllers) (Cgroup, error) {
	if DetectedCgroupType == TypeV1 {
		return openExistingV1(prefix, ct)
	}
	return openExistingV2(prefix, ct)
}

func openExistingV1(prefix string, ct *Controllers) (cg Cgroup, err error) {
	v1 := &V1{
		prefix:   prefix,
		existing: true,
	}

	if err = loopV1Controllers(ct, v1, func(name string, cg **v1controller) error {
		p := path.Join(basePath, name, prefix)
		*cg = newV1Controller(p)
		// os.IsNotExist
		if _, err := os.Stat(p); err != nil {
			return err
		}
		v1.all = append(v1.all, *cg)
		return nil
	}); err != nil {
		return
	}

	// init cpu set before use, otherwise it is not functional
	if v1.cpuset != nil {
		if err = initCpuset(v1.cpuset.path); err != nil {
			return
		}
	}
	return
}

func openExistingV2(prefix string, ct *Controllers) (cg Cgroup, err error) {
	ect, err := getAvailableControllerV2(prefix)
	if err != nil {
		return nil, err
	}
	if !ect.Contains(ct) {
		return nil, fmt.Errorf("openCgroupV2: requesting %v controllers but %v found", ct, ect)
	}
	return &V2{
		path:     path.Join(basePath, prefix),
		existing: true,
	}, nil
}
