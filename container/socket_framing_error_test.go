package container

import (
	"strings"
	"syscall"
	"testing"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

// sendRawChunk writes a raw [chunkByte][flag][payload] chunk datagram for testing.
func sendRawChunk(t *testing.T, s *unixsocket.Socket, flag byte, payload []byte, fds []int) {
	t.Helper()
	frame := make([]byte, chunkHeaderSize+len(payload))
	frame[0] = chunkByte
	frame[1] = flag
	copy(frame[chunkHeaderSize:], payload)
	msg := unixsocket.Msg{}
	if len(fds) > 0 {
		msg.Fds = fds
	}
	if err := s.SendMsg(frame, msg); err != nil {
		t.Fatalf("sendRawChunk: %v", err)
	}
}

// TestChunkUnexpectedFDsInLaterChunk verifies FDs carried on a non-first chunk
// are closed and rejected (FDs only travel with the first chunk).
func TestChunkUnexpectedFDsInLaterChunk(t *testing.T) {
	server, client, err := unixsocket.NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer client.Close()

	cli := newSocket(client)

	pipe := make([]int, 2)
	openPipe(t, pipe)
	defer closeFds(pipe)

	// First chunk (partial) without FDs, second chunk carries unexpected FDs.
	sendRawChunk(t, server, chunkPartial, []byte("hello"), nil)
	sendRawChunk(t, server, chunkComplete, []byte("world"), []int{pipe[0]})

	var out cmd
	_, err = cli.RecvMsg(&out)
	if err == nil {
		t.Fatal("expected error for unexpected FDs in chunk, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected FDs") {
		t.Errorf("error = %v, want contains 'unexpected FDs'", err)
	}
}

// TestChunkedMediumRoundTrip verifies a message a few hundred KB in size is
// chunked and reassembled correctly (multiple partial chunks + one complete).
func TestChunkedMediumRoundTrip(t *testing.T) {
	server, client, err := unixsocket.NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer client.Close()

	cli := newSocket(client)

	paths := make([]OpenCmd, 2000)
	for i := range paths {
		paths[i] = OpenCmd{Path: "/w/" + strings.Repeat("p", 200)}
	}
	errCh := make(chan error, 1)
	go func() {
		var c cmd
		_, e := newSocket(server).RecvMsg(&c)
		if e == nil && len(c.OpenCmd) != 2000 {
			t.Errorf("got %d cmds, want 2000", len(c.OpenCmd))
		}
		errCh <- e
	}()
	if err := cli.SendMsg(cmd{Cmd: cmdOpen, OpenCmd: paths}, unixsocket.Msg{}); err != nil {
		t.Fatalf("send large chunked: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("recv large chunked: %v", err)
	}
}

// TestChunkRoundTripLarge sends a message far larger than a single datagram and
// verifies it is chunked and reassembled intact, then a small message still works.
func TestChunkRoundTripLarge(t *testing.T) {
	server, client, err := unixsocket.NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer client.Close()

	srv := newSocket(server)
	cli := newSocket(client)

	// ~3000 paths of 200 chars -> hundreds of KB, many chunks.
	paths := make([]OpenCmd, 3000)
	for i := range paths {
		paths[i] = OpenCmd{Path: "/w/" + strings.Repeat("z", 200)}
	}

	errCh := make(chan error, 1)
	go func() {
		var c cmd
		if _, e := srv.RecvMsg(&c); e != nil {
			errCh <- e
			return
		}
		if len(c.OpenCmd) != 3000 {
			t.Errorf("large: got %d cmds, want 3000", len(c.OpenCmd))
		}
		// A small message after a large one must still work (assembly buffer reset).
		var c2 cmd
		_, e := srv.RecvMsg(&c2)
		if e == nil && c2.Cmd != cmdPing {
			t.Errorf("small after large: got cmd %d, want cmdPing", c2.Cmd)
		}
		errCh <- e
	}()

	if err := cli.SendMsg(cmd{Cmd: cmdOpen, OpenCmd: paths}, unixsocket.Msg{}); err != nil {
		t.Fatalf("send large: %v", err)
	}
	if err := cli.SendMsg(cmd{Cmd: cmdPing}, unixsocket.Msg{}); err != nil {
		t.Fatalf("send small after large: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("recv: %v", err)
	}
}

// TestChunkUnlimitedSize verifies a message several MB in size (far beyond a
// single SEQPACKET datagram / the default kernel socket buffer) round-trips
// intact, proving chunking has no practical size ceiling and needs no kernel
// buffer tuning.
func TestChunkUnlimitedSize(t *testing.T) {
	server, client, err := unixsocket.NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer client.Close()

	srv := newSocket(server)
	cli := newSocket(client)

	// ~40000 paths of 200 chars -> ~8MB gob, hundreds of chunks, well past the
	// ~200KB single-datagram kernel limit.
	paths := make([]OpenCmd, 40000)
	for i := range paths {
		paths[i] = OpenCmd{Path: "/w/" + strings.Repeat("u", 200)}
	}

	errCh := make(chan error, 1)
	go func() {
		var c cmd
		_, e := srv.RecvMsg(&c)
		if e == nil && len(c.OpenCmd) != 40000 {
			t.Errorf("got %d cmds, want 40000", len(c.OpenCmd))
		}
		errCh <- e
	}()

	if err := cli.SendMsg(cmd{Cmd: cmdOpen, OpenCmd: paths}, unixsocket.Msg{}); err != nil {
		t.Fatalf("send multi-MB: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("recv multi-MB: %v", err)
	}
}

// TestSmallMessageNoChunkHeader verifies small messages are sent raw with no
// chunk header: a direct raw recv sees a first byte that is not chunkByte.
func TestSmallMessageNoChunkHeader(t *testing.T) {
	server, client, err := unixsocket.NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer client.Close()

	cli := newSocket(client)

	if err := cli.SendMsg(cmd{Cmd: cmdPing}, unixsocket.Msg{}); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, bufferSize)
	n, _, err := server.RecvMsg(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatal("empty datagram")
	}
	if buf[0] == chunkByte {
		t.Errorf("small message unexpectedly sent as a chunk (first byte=0x%02x)", buf[0])
	}
}

// openPipe is a helper to create a pipe for FD passing tests
func openPipe(t *testing.T, p []int) {
	t.Helper()
	if err := syscall.Pipe2(p, syscall.O_CLOEXEC); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
}
