package cgroup

import (
	"io/ioutil"
	"os"
	"path"
)

// EnsureDirExists creates dir if not exists
func EnsureDirExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.Mkdir(path, os.ModePerm)
	}
	return nil
}

// CreateSubCGroupPath creates path for sub-cgroup
func CreateSubCGroupPath(group, prefix string) (string, error) {
	base := path.Join(basePath, group, prefix)
	EnsureDirExists(base)
	return ioutil.TempDir(base, "")
}
