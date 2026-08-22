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
	defer a.Close()
	defer b.Close()

	m := make([]byte, 1024)
	errCh := make(chan error, 1)

	go func() {
		msg := []byte("message")
		errCh <- a.SendMsg(msg, Msg{})
	}()

	n, _, err := b.RecvMsg(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
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
	cred := &syscall.Ucred{
		Pid: int32(os.Getpid()),
		Uid: uint32(os.Getuid()),
		Gid: uint32(os.Getgid()),
	}
	if err := a.SendMsg(msg, Msg{Cred: cred}); err != nil {
		t.Fatal(err)
	}

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
	} else if *m.Cred != *cred {
		t.Errorf("credential = %+v, want %+v", *m.Cred, *cred)
	}
}

func TestSendRecvMsg_MultipleFds(t *testing.T) {
	a, b, err := NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()

	files := make([]*os.File, 3)
	fds := make([]int, len(files))
	for i := range files {
		files[i], err = os.CreateTemp(t.TempDir(), "unixsocket-fd")
		if err != nil {
			t.Fatal(err)
		}
		defer files[i].Close()
		fds[i] = int(files[i].Fd())
	}

	if err := a.SendMsg([]byte("fds"), Msg{Fds: fds}); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 16)
	n, msg, err := b.RecvMsg(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], []byte("fds")) {
		t.Errorf("payload = %q, want %q", buf[:n], "fds")
	}
	if len(msg.Fds) != len(fds) {
		t.Fatalf("received %d FDs, want %d", len(msg.Fds), len(fds))
	}
	for _, fd := range msg.Fds {
		if err := syscall.Close(fd); err != nil {
			t.Errorf("close received fd %d: %v", fd, err)
		}
	}
}

func TestRecvMsg_PayloadTruncated(t *testing.T) {
	a, b, err := NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()

	if err := a.SendMsg([]byte("message"), Msg{}); err != nil {
		t.Fatal(err)
	}

	_, _, err = b.RecvMsg(make([]byte, 1))
	if err != errMessageTruncated {
		t.Fatalf("RecvMsg error = %v, want %v", err, errMessageTruncated)
	}
}

func TestSendRecvMsg_ClosedSocket(t *testing.T) {
	a, b, err := NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	defer a.Close()

	if err := b.SendMsg([]byte("message"), Msg{}); err == nil {
		t.Error("SendMsg on closed socket returned nil")
	}
	if _, _, err := b.RecvMsg(make([]byte, 16)); err == nil {
		t.Error("RecvMsg on closed socket returned nil")
	}
}

func TestNewSocket_NonSocketFd(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "unixsocket-nonsocket")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if _, err := NewSocket(int(file.Fd())); err == nil {
		t.Error("NewSocket(non-socket fd) returned nil error")
	}
}

func TestParseMsg_MalformedCredentials(t *testing.T) {
	_, err := parseMsg([]syscall.SocketControlMessage{{
		Header: syscall.Cmsghdr{
			Level: syscall.SOL_SOCKET,
			Type:  syscall.SCM_CREDENTIALS,
		},
	}})
	if err == nil {
		t.Error("parseMsg(malformed credentials) returned nil error")
	}
}

func TestParseMsg_ClosesFdsOnError(t *testing.T) {
	pipe := make([]int, 2)
	if err := syscall.Pipe(pipe); err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(pipe[1])

	rights, err := syscall.ParseSocketControlMessage(syscall.UnixRights(pipe[0]))
	if err != nil {
		t.Fatal(err)
	}
	_, err = parseMsg(append(rights,
		syscall.SocketControlMessage{Header: syscall.Cmsghdr{
			Level: syscall.SOL_SOCKET,
			Type:  syscall.SCM_CREDENTIALS,
		}},
	))
	if err == nil {
		t.Fatal("parseMsg returned nil error")
	}
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(pipe[0]), uintptr(syscall.F_GETFD), 0)
	if errno == 0 {
		t.Error("parseMsg did not close received FD after error")
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
