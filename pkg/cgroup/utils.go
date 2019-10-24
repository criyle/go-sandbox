package cgroup

import (
	"bufio"
	"io/ioutil"
	"os"
	"path"
	"strings"
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

// GetAllSubCgroup reads /proc/cgroups and get all avaliable sub-cgroup as set
func GetAllSubCgroup() (map[string]bool, error) {
	f, err := os.Open(procCgroupsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rt := make(map[string]bool)
	s := bufio.NewScanner(f)
	for s.Scan() {
		text := s.Text()
		if text[0] != '#' {
			parts := strings.Fields(text)
			if len(parts) >= 4 && parts[3] != "0" {
				rt[parts[0]] = true
			}
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return rt, nil
}
