package cgroup

import (
	"errors"
	"io/fs"
	"os"
	"path"
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

// CreateSubCgroupPath creates path for controller with given group and prefix
func CreateV1ControllerPath(controller, prefix string) (string, error) {
	base := path.Join(basePath, controller, prefix)
	EnsureDirExists(base)
	return os.MkdirTemp(base, "")
}

// CreateV1ControllerPathName create path for controller with given group, prefix and name
func CreateV1ControllerPathName(controller, prefix, name string) (string, error) {
	p := path.Join(basePath, controller, prefix, name)
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
		procFile.WriteString(v)
	}
	procFile.Close()

	a, err := GetAvailableControllerV2()
	if err != nil {
		return err
	}
	s := make([]string, 0, len(a))
	for k := range a {
		s = append(s, k)
	}
	controlMsg := []byte("+" + strings.Join(s, " +"))
	if err := writeFile(path.Join(basePath, cgroupSubtreeControl), controlMsg, filePerm); err != nil {
		return err
	}
	return nil
}

// DetectType detects current mounted cgroup type in systemd default path
func DetectType() CgroupType {
	// if /sys/fs/cgroup is mounted as CGROUPV2 or TMPFS (V1)
	var st unix.Statfs_t
	if err := unix.Statfs(basePath, &st); err != nil {
		// ignore errors, defalting to CgroupV1
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
