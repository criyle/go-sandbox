package cgroup

import (
	"io/ioutil"
	"os"
	"path"
)

// EnsureDirExists creates directories if the path not exists
func EnsureDirExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, dirPerm)
	}
	return nil
}

// CreateSubCgroupPath creates path for sub-cgroup with given group and prefix
func CreateSubCgroupPath(group, prefix string) (string, error) {
	base := path.Join(basePath, group, prefix)
	EnsureDirExists(base)
	return ioutil.TempDir(base, "")
}
