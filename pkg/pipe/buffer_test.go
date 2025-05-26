package pipe

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestNewBuffer_WriteAndRead(t *testing.T) {
	const max = 10
	buf, err := NewBuffer(max)
	if err != nil {
		t.Fatalf("NewBuffer error: %v", err)
	}
	defer buf.W.Close()

	// Write less than max bytes
	input := "hello"
	n, err := buf.W.Write([]byte(input))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(input) {
		t.Errorf("Write bytes = %d, want %d", n, len(input))
	}
	buf.W.Close()
	<-buf.Done

	got := buf.Buffer.String()
	if got != input {
		t.Errorf("Buffer content = %q, want %q", got, input)
	}
}

func TestNewBuffer_MaxBytes(t *testing.T) {
	const max = 5
	buf, err := NewBuffer(max)
	if err != nil {
		t.Fatalf("NewBuffer error: %v", err)
	}
	defer buf.W.Close()

	// Write more than max bytes
	input := "toolonginput"
	_, err = io.Copy(buf.W, strings.NewReader(input))
	if err != nil {
		t.Fatalf("Copy error: %v", err)
	}
	buf.W.Close()
	<-buf.Done

	got := buf.Buffer.String()
	if len(got) != int(max+1) {
		t.Errorf("Buffer length = %d, want %d", len(got), max+1)
	}
	if got != input[:max+1] {
		t.Errorf("Buffer content = %q, want %q", got, input[:max+1])
	}
}

func TestBuffer_String(t *testing.T) {
	const max = 8
	buf, err := NewBuffer(max)
	if err != nil {
		t.Fatalf("NewBuffer error: %v", err)
	}
	defer buf.W.Close()

	_, _ = buf.W.Write([]byte("abc"))
	buf.W.Close()
	<-buf.Done

	want := "Buffer[3/8]"
	if buf.String() != want {
		t.Errorf("String() = %q, want %q", buf.String(), want)
	}
}

func TestNewBuffer_DoneCloses(t *testing.T) {
	const max = 4
	buf, err := NewBuffer(max)
	if err != nil {
		t.Fatalf("NewBuffer error: %v", err)
	}
	defer buf.W.Close()

	done := make(chan struct{})
	go func() {
		_, _ = buf.W.Write([]byte("test"))
		buf.W.Close()
		close(done)
	}()

	select {
	case <-buf.Done:
		// ok
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for Done channel")
	}
}
