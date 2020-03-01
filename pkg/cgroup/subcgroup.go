package cgroup

import (
	"errors"
	"io/ioutil"
	"path"
	"strconv"
	"strings"
	"syscall"
)

// SubCGroup is the sub-cgroup
type SubCGroup struct {
	path string
}

// ErrNotInitialized returned when trying to read from not initialized cgroup
var ErrNotInitialized = errors.New("cgroup was not initialized")

// NewSubCGroup creates a sug CGroup
func NewSubCGroup(p string) *SubCGroup {
	return &SubCGroup{
		path: p,
	}
}

// WriteUint writes uint64 into given file
func (c *SubCGroup) WriteUint(filename string, i uint64) error {
	if c.path == "" {
		return nil
	}
	return c.WriteFile(filename, []byte(strconv.FormatUint(i, 10)))
}

// ReadUint read uint64 into given file
func (c *SubCGroup) ReadUint(filename string) (uint64, error) {
	if c.path == "" {
		return 0, ErrNotInitialized
	}
	b, err := c.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	s, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, err
	}
	return s, nil
}

// WriteFile writes cgroup file and handles potential EINTR error while writes to
// the slow device (cgroup)
func (c *SubCGroup) WriteFile(name string, content []byte) error {
	p := path.Join(c.path, name)
	err := ioutil.WriteFile(p, content, 0664)
	for err != nil && errors.Is(err, syscall.EINTR) {
		err = ioutil.WriteFile(p, content, 0664)
	}
	return err
}

// ReadFile reads cgroup file and handles potential EINTR error while read to
// the slow device (cgroup)
func (c *SubCGroup) ReadFile(name string) ([]byte, error) {
	p := path.Join(c.path, name)
	data, err := ioutil.ReadFile(p)
	for err != nil && errors.Is(err, syscall.EINTR) {
		data, err = ioutil.ReadFile(p)
	}
	return data, err
}
