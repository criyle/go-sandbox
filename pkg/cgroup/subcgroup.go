package cgroup

import (
	"errors"
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
	return writeFileNoInterrupt(path.Join(c.path, filename), []byte(strconv.FormatUint(i, 10)))
}

// ReadUint read uint64 into given file
func (c *SubCGroup) ReadUint(filename string) (uint64, error) {
	if c.path == "" {
		return 0, ErrNotInitialized
	}
	b, err := readFileNoInterrupt(path.Join(c.path, filename))
	if err != nil {
		return 0, err
	}
	s, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, err
	}
	return s, nil
}

// writeFileNoInterrupt handles potential EINTR error while writes to
// the slow device (cgroup)
func writeFileNoInterrupt(path string, content []byte) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_TRUNC|syscall.O_CLOEXEC, 0664)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	_, err = syscall.Write(fd, content)
	for err == syscall.EINTR {
		_, err = syscall.Write(fd, content)
	}
	return nil
}

const maxUintFile = 64 // max file size 64 bytes (enough for uint)

// readFileNoInterrupt handles potential EINTR error while read to
// the slow device (cgroup)
func readFileNoInterrupt(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0664)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)

	buff := make([]byte, maxUintFile)
	n, err := syscall.Read(fd, buff)
	for err == syscall.EINTR {
		n, err = syscall.Read(fd, buff)
	}
	return buff[:n], nil
}
