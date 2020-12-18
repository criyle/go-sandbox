package cgroup

import (
	"errors"
	"io/ioutil"
	"path"
	"strconv"
	"strings"
	"syscall"
)

// SubCgroup is the accessor for single cgroup resource with given path
type SubCgroup struct {
	path string
}

// ErrNotInitialized returned when trying to read from not initialized cgroup
var ErrNotInitialized = errors.New("cgroup was not initialized")

// NewSubCgroup creates a cgroup accessor with given path (path needs to be created in advance)
func NewSubCgroup(p string) *SubCgroup {
	return &SubCgroup{path: p}
}

// WriteUint writes uint64 into given file
func (c *SubCgroup) WriteUint(filename string, i uint64) error {
	if c == nil || c.path == "" {
		return nil
	}
	return c.WriteFile(filename, []byte(strconv.FormatUint(i, 10)))
}

// ReadUint read uint64 from given file
func (c *SubCgroup) ReadUint(filename string) (uint64, error) {
	if c == nil || c.path == "" {
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
func (c *SubCgroup) WriteFile(name string, content []byte) error {
	if c == nil || c.path == "" {
		return ErrNotInitialized
	}
	p := path.Join(c.path, name)
	err := ioutil.WriteFile(p, content, filePerm)
	for err != nil && errors.Is(err, syscall.EINTR) {
		err = ioutil.WriteFile(p, content, filePerm)
	}
	return err
}

// ReadFile reads cgroup file and handles potential EINTR error while read to
// the slow device (cgroup)
func (c *SubCgroup) ReadFile(name string) ([]byte, error) {
	if c == nil || c.path == "" {
		return nil, nil
	}
	p := path.Join(c.path, name)
	data, err := ioutil.ReadFile(p)
	for err != nil && errors.Is(err, syscall.EINTR) {
		data, err = ioutil.ReadFile(p)
	}
	return data, err
}
