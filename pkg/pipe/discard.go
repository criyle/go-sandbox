package pipe

import (
	"io"
	"os"
)

var _ io.Writer = discardWriter{}

type discardWriter struct {
}

func (w discardWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func discardRead(f *os.File) (int64, error) {
	return io.Copy(discardWriter{}, f)
}
