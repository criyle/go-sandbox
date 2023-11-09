package cgroup

import (
	"errors"
	"path"
	"strconv"
	"strings"
)

// v1controller is the accessor for single cgroup resource with given path
type v1controller struct {
	path string
}

// ErrNotInitialized returned when trying to read from not initialized cgroup
var ErrNotInitialized = errors.New("cgroup was not initialized")

// NewV1Controller creates a cgroup accessor with given path (path needs to be created in advance)
func NewV1Controller(p string) *v1controller {
	return &v1controller{path: p}
}

// WriteUint writes uint64 into given file
func (c *v1controller) WriteUint(filename string, i uint64) error {
	if c == nil || c.path == "" {
		return nil
	}
	return c.WriteFile(filename, []byte(strconv.FormatUint(i, 10)))
}

// ReadUint read uint64 from given file
func (c *v1controller) ReadUint(filename string) (uint64, error) {
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
func (c *v1controller) WriteFile(name string, content []byte) error {
	if c == nil || c.path == "" {
		return ErrNotInitialized
	}
	p := path.Join(c.path, name)
	return writeFile(p, content, filePerm)
}

// ReadFile reads cgroup file and handles potential EINTR error while read to
// the slow device (cgroup)
func (c *v1controller) ReadFile(name string) ([]byte, error) {
	if c == nil || c.path == "" {
		return nil, nil
	}
	p := path.Join(c.path, name)
	return readFile(p)
}

func (c *v1controller) AddProc(pids ...int) error {
	return AddProcesses(path.Join(c.path, cgroupProcs), pids)
}
