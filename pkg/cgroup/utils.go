package cgroup

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
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
