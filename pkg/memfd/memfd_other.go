//go:build !linux

package memfd

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

var errNotImplemented = fmt.Errorf("memfd: unsupported on platform %s", runtime.GOOS)

func New(name string) (*os.File, error) {
	return nil, errNotImplemented
}

func DupToMemfd(name string, reader io.Reader) (*os.File, error) {
	return nil, errNotImplemented
}
