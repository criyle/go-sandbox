package cgroup

import (
	"io/ioutil"
	"path"
	"strconv"
	"strings"
)

// SubCGroup is the sub-cgroup
type SubCGroup struct {
	path string
}

// NewSubCGroup creates a sug CGroup
func NewSubCGroup(p string) *SubCGroup {
	return &SubCGroup{
		path: p,
	}
}

// WriteUint writes uint64 into given file
func (c *SubCGroup) WriteUint(filename string, i uint64) error {
	return ioutil.WriteFile(path.Join(c.path, filename), []byte(strconv.FormatUint(i, 10)), 644)
}

// ReadUint read uint64 into given file
func (c *SubCGroup) ReadUint(filename string) (uint64, error) {
	b, err := ioutil.ReadFile(path.Join(c.path, filename))
	if err != nil {
		return 0, err
	}
	s, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, err
	}
	return s, nil
}
