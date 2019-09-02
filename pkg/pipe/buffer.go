// Package pipe provides a wrapper to create a pipe and
// read at most max content from the reader side
package pipe

import (
	"bytes"
	"io"
	"os"
)

// Buffer is used to create a writable pipe and read
// at most max bytes to a buffer
type Buffer struct {
	W      *os.File
	Max    int64
	Buffer *bytes.Buffer
	Done   <-chan struct{}
}

// NewPipe create a pipe with a goroutine to copy its read-end to writer
// returns the write end and signal for finish
// caller need to close w
func NewPipe(writer io.Writer, n int64) (<-chan struct{}, *os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer r.Close()
		io.CopyN(writer, r, int64(n))
	}()
	return done, w, nil
}

// NewBuffer creates a os pipe, caller need to
// caller need to close w
// Notice: if rely on doen for finish, w need be closed in parent process
func NewBuffer(max int64) (*Buffer, error) {
	buffer := new(bytes.Buffer)
	done, w, err := NewPipe(buffer, max+1)
	if err != nil {
		return nil, err
	}
	return &Buffer{
		W:      w,
		Max:    max,
		Buffer: buffer,
		Done:   done,
	}, nil
}
