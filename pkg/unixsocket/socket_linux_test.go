package unixsocket

import (
	"bytes"
	"os"
	"syscall"
	"testing"
)

func TestBaseline(t *testing.T) {
	a, b, err := NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	m := make([]byte, 1024)

	go func() {
		msg := []byte("message")
		a.SendMsg(msg, Msg{})
	}()

	n, _, err := b.RecvMsg(m)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(m[:n], []byte("message")) {
		t.Fatal("not equal")
	}
}

func TestSendRecvMsg_Fds(t *testing.T) {
	a, b, err := NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()

	// Create a file to send its fd
	tmpfile, err := os.CreateTemp("", "unixsocket-fd")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	msg := []byte("fdtest")
	go func() {
		a.SendMsg(msg, Msg{Fds: []int{int(tmpfile.Fd())}})
	}()

	buf := make([]byte, 64)
	n, m, err := b.RecvMsg(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Errorf("RecvMsg got %q, want %q", buf[:n], msg)
	}
	if len(m.Fds) != 1 {
		t.Errorf("expected 1 fd, got %d", len(m.Fds))
	}
	if m.Fds != nil {
		syscall.Close(m.Fds[0])
	}
}

func TestSendRecvMsg_Cred(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping credential test: requires root privileges")
		return
	}
	a, b, err := NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()

	// Enable credential passing
	if err := a.SetPassCred(1); err != nil {
		t.Fatal(err)
	}
	if err := b.SetPassCred(1); err != nil {
		t.Fatal(err)
	}

	msg := []byte("credtest")
	go func() {
		a.SendMsg(msg, Msg{Cred: &syscall.Ucred{Pid: 123, Uid: 456, Gid: 789}})
	}()

	buf := make([]byte, 64)
	n, m, err := b.RecvMsg(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Errorf("RecvMsg got %q, want %q", buf[:n], msg)
	}
	if m.Cred == nil {
		t.Error("expected credential, got nil")
	}
}

func TestNewSocketPair_Close(t *testing.T) {
	a, b, err := NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("a.Close() error: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("b.Close() error: %v", err)
	}
}

func TestNewSocket_InvalidFd(t *testing.T) {
	// Use an invalid fd
	_, err := NewSocket(-1)
	if err == nil {
		t.Error("expected error for invalid fd, got nil")
	}
}

func TestSetPassCred_InvalidSocket(t *testing.T) {
	a, b, err := NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()

	// Close the socket to make it invalid
	a.Close()
	err = a.SetPassCred(1)
	if err == nil {
		t.Error("expected error on SetPassCred for closed socket, got nil")
	}
}
