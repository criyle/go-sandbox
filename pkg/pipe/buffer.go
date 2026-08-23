// Package pipe provides wrappers to create pipes and collect bounded output
// from their reader side. NewBuffer retains max+1 bytes intentionally: the
// extra byte is a sentinel that lets callers distinguish output at or below
// the limit from output that exceeded it.
package pipe

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// Buffer is used to create a writable pipe and read
// at most max bytes to a buffer
type Buffer struct {
	W      *os.File
	Buffer *bytes.Buffer
	Done   <-chan struct{}
	Max    int64
}

// NewPipe creates a pipe with a goroutine that copies at most n bytes from its
// read end to writer. It returns the write end and a signal that the bounded
// copy has finished. Errors from the bounded copy and the subsequent drain are
// intentionally ignored.
//
// Once n bytes have been copied, the goroutine closes done and continues
// reading and discarding input until w is closed. This drain prevents the
// producer on the other end from blocking or receiving SIGPIPE, but means
// that done does not signal that the goroutine has exited. The caller must
// close w to let the drain finish.
func NewPipe(writer io.Writer, n int64) (<-chan struct{}, *os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	done := make(chan struct{})
	go func() {
		io.CopyN(writer, r, int64(n))
		close(done)
		// ensure no blocking / SIGPIPE on the other end
		io.Copy(io.Discard, r)
		r.Close()
	}()
	return done, w, nil
}

// NewBuffer creates an os pipe backed by a bytes.Buffer. It copies max+1
// bytes, retaining one sentinel byte so callers can determine whether the
// output exceeded max. Consequently, Buffer may contain max+1 bytes.
//
// Done signals that the bounded copy is complete; the pipe goroutine may
// still be draining and discarding further input. The caller must close W,
// including when relying on Done, so that drain can finish.
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

func (b Buffer) String() string {
	return fmt.Sprintf("Buffer[%d/%d]", b.Buffer.Len(), b.Max)
}
