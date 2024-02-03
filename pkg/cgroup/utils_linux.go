package cgroup

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// EnsureDirExists creates directories if the path not exists
func EnsureDirExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, dirPerm)
	}
	return os.ErrExist
}

// CreateV1ControllerPath create path for controller with given group, prefix
func CreateV1ControllerPath(controller, prefix string) (string, error) {
	p := path.Join(basePath, controller, prefix)
	return p, EnsureDirExists(p)
}

const initPath = "init"

// EnableV2Nesting migrates all process in the container to nested /init path
// and enables all available controllers in the root cgroup
func EnableV2Nesting() error {
	if DetectType() != CgroupTypeV2 {
		return nil
	}

	p, err := readFile(path.Join(basePath, cgroupProcs))
	if err != nil {
		return err
	}
	procs := strings.Split(string(p), "\n")
	if len(procs) == 0 {
		return nil
	}

	// mkdir init
	if err := os.Mkdir(path.Join(basePath, initPath), dirPerm); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	// move all process into init cgroup
	procFile, err := os.OpenFile(path.Join(basePath, initPath, cgroupProcs), os.O_RDWR, filePerm)
	if err != nil {
		return err
	}
	for _, v := range procs {
		if _, err := procFile.WriteString(v); err != nil {
			continue
			//return err
		}
	}
	procFile.Close()
	return nil
}

// ReadProcesses reads cgroup.procs file and return pids individually
func ReadProcesses(path string) ([]int, error) {
	content, err := readFile(path)
	if err != nil {
		return nil, err
	}
	procs := strings.Split(string(content), "\n")
	rt := make([]int, len(procs))
	for i, x := range procs {
		if len(x) == 0 {
			continue
		}
		rt[i], err = strconv.Atoi(x)
		if err != nil {
			return nil, err
		}
	}
	return rt, nil
}

// Add Processes add processes into cgroup.procs file
func AddProcesses(path string, procs []int) error {
	f, err := os.OpenFile(path, os.O_RDWR, filePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, p := range procs {
		if _, err := f.WriteString(strconv.Itoa(p)); err != nil {
			return err
		}
	}
	return nil
}

// DetectType detects current mounted cgroup type in systemd default path
func DetectType() CgroupType {
	// if /sys/fs/cgroup is mounted as CGROUPV2 or TMPFS (V1)
	var st unix.Statfs_t
	if err := unix.Statfs(basePath, &st); err != nil {
		// ignore errors, defaulting to CgroupV1
		return CgroupTypeV1
	}
	if st.Type == unix.CGROUP2_SUPER_MAGIC {
		return CgroupTypeV2
	}
	return CgroupTypeV1
}

func remove(name string) error {
	if name != "" {
		return os.Remove(name)
	}
	return nil
}

var errPatternHasSeparator = errors.New("pattern contains path separator")

// prefixAndSuffix splits pattern by the last wildcard "*", if applicable,
// returning prefix as the part before "*" and suffix as the part after "*".
func prefixAndSuffix(pattern string) (prefix, suffix string, err error) {
	for i := 0; i < len(pattern); i++ {
		if os.IsPathSeparator(pattern[i]) {
			return "", "", errPatternHasSeparator
		}
	}
	if pos := strings.LastIndexByte(pattern, '*'); pos != -1 {
		prefix, suffix = pattern[:pos], pattern[pos+1:]
	} else {
		prefix = pattern
	}
	return prefix, suffix, nil
}

func readFile(p string) ([]byte, error) {
	data, err := os.ReadFile(p)
	for err != nil && errors.Is(err, syscall.EINTR) {
		data, err = os.ReadFile(p)
	}
	return data, err
}

func writeFile(p string, content []byte, perm fs.FileMode) error {
	err := os.WriteFile(p, content, filePerm)
	for err != nil && errors.Is(err, syscall.EINTR) {
		err = os.WriteFile(p, content, filePerm)
	}
	return err
}

func nextRandom() string {
	return strconv.Itoa(int(rand.Int31()))
}

// randomBuild creates a cgroup with random directory, similar to os.MkdirTemp
func randomBuild(pattern string, build func(string) (Cgroup, error)) (Cgroup, error) {
	prefix, suffix, err := prefixAndSuffix(pattern)
	if err != nil {
		return nil, fmt.Errorf("cgroup.builder: random %v", err)
	}

	try := 0
	for {
		name := prefix + nextRandom() + suffix
		cg, err := build(name)
		if err == nil {
			return cg, nil
		}
		if errors.Is(err, os.ErrExist) || cg.Existing() {
			if try++; try < 10000 {
				continue
			}
			return nil, fmt.Errorf("cgroup.builder: tried 10000 times but failed")
		}
		return nil, fmt.Errorf("cgroup.builder: random %v", err)
	}
}
