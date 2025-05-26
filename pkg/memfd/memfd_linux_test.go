package memfd

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestNew(t *testing.T) {
	f, err := New("test-memfd")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer f.Close()

	// Write and read to verify it's a valid file
	data := []byte("hello world")
	n, err := f.Write(data)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write n = %d, want %d", n, len(data))
	}
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatalf("Seek error: %v", err)
	}
	read := make([]byte, len(data))
	n, err = f.Read(read)
	if err != nil && err != io.EOF {
		t.Fatalf("Read error: %v", err)
	}
	if string(read[:n]) != string(data) {
		t.Errorf("Read = %q, want %q", string(read[:n]), string(data))
	}
}

func TestDupToMemfd(t *testing.T) {
	content := []byte("memfd content")
	r := bytes.NewReader(content)
	f, err := DupToMemfd("dup-memfd", r)
	if err != nil {
		t.Fatalf("DupToMemfd error: %v", err)
	}
	defer f.Close()

	// Should be sealed (readonly), so writing should fail
	_, err = f.Write([]byte("fail"))
	if err == nil {
		t.Error("expected write to sealed memfd to fail, but it succeeded")
	}

	// Should be able to read the content
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatalf("Seek error: %v", err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("ReadAll = %q, want %q", string(got), string(content))
	}
}

func TestDupToMemfd_ErrorPropagation(t *testing.T) {
	// Pass a reader that always errors
	r := errorReader{}
	_, err := DupToMemfd("dup-memfd-err", r)
	if err == nil {
		t.Error("expected error from DupToMemfd, got nil")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, os.ErrInvalid }
