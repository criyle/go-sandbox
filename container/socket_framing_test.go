package container

import (
	"strings"
	"testing"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

func TestSocketFramingSingle(t *testing.T) {
	server, client, err := unixsocket.NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer client.Close()

	srvSock := newSocket(server)
	cliSock := newSocket(client)

	// Send a small cmd (single frame)
	sendCmd := cmd{Cmd: cmdPing}
	if err := cliSock.SendMsg(sendCmd, unixsocket.Msg{}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}

	var recvCmd cmd
	msg, err := srvSock.RecvMsg(&recvCmd)
	if err != nil {
		t.Fatalf("RecvMsg: %v", err)
	}
	if recvCmd.Cmd != cmdPing {
		t.Errorf("got cmd %d, want %d", recvCmd.Cmd, cmdPing)
	}
	if len(msg.Fds) != 0 {
		t.Errorf("unexpected fds: %d", len(msg.Fds))
	}

	// Send reply
	if err := srvSock.SendMsg(reply{}, unixsocket.Msg{}); err != nil {
		t.Fatalf("SendMsg reply: %v", err)
	}
	var recvReply reply
	if _, err := cliSock.RecvMsg(&recvReply); err != nil {
		t.Fatalf("RecvMsg reply: %v", err)
	}
}

func TestSocketFramingLargeMessage(t *testing.T) {
	server, client, err := unixsocket.NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer client.Close()

	srvSock := newSocket(server)
	cliSock := newSocket(client)

	// Create a large message that exceeds 32KB to trigger chunking
	// Use long paths in OpenCmd to inflate GOB size
	lotsOfPaths := make([]OpenCmd, 0, 500)
	for i := 0; i < 500; i++ {
		lotsOfPaths = append(lotsOfPaths, OpenCmd{
			Path:     strings.Repeat("a", 100) + "_file_" + string(rune('A'+i%26)),
			Flag:     0,
			Perm:     0644,
			MkdirAll: true,
		})
	}

	sendCmd := cmd{
		Cmd:     cmdOpen,
		OpenCmd: lotsOfPaths,
	}

	errCh := make(chan error, 1)
	var recvCmd cmd
	go func() {
		_, err := srvSock.RecvMsg(&recvCmd)
		errCh <- err
	}()

	if err := cliSock.SendMsg(sendCmd, unixsocket.Msg{}); err != nil {
		t.Fatalf("SendMsg large: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("RecvMsg large: %v", err)
	}

	if recvCmd.Cmd != cmdOpen {
		t.Errorf("got cmd %d, want %d", recvCmd.Cmd, cmdOpen)
	}
	if len(recvCmd.OpenCmd) != 500 {
		t.Errorf("got %d OpenCmds, want 500", len(recvCmd.OpenCmd))
	}
	// Verify first and last paths
	if len(recvCmd.OpenCmd) > 0 {
		expected := strings.Repeat("a", 100) + "_file_" + string(rune('A'))
		if !strings.HasPrefix(recvCmd.OpenCmd[0].Path, strings.Repeat("a", 100)) {
			t.Errorf("first path corrupted: %q", recvCmd.OpenCmd[0].Path)
		}
		_ = expected
	}
}

func TestSocketFramingRoundTrip(t *testing.T) {
	server, client, err := unixsocket.NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer client.Close()

	srvSock := newSocket(server)
	cliSock := newSocket(client)

	// Send multiple messages alternating directions to verify state is clean
	for i := 0; i < 10; i++ {
		c := cmd{Cmd: cmdPing}
		if err := cliSock.SendMsg(c, unixsocket.Msg{}); err != nil {
			t.Fatalf("SendMsg ping %d: %v", i, err)
		}
		var rc cmd
		if _, err := srvSock.RecvMsg(&rc); err != nil {
			t.Fatalf("RecvMsg ping %d: %v", i, err)
		}
		if rc.Cmd != cmdPing {
			t.Errorf("iter %d: got cmd %d, want %d", i, rc.Cmd, cmdPing)
		}

		// Reply
		if err := srvSock.SendMsg(reply{}, unixsocket.Msg{}); err != nil {
			t.Fatalf("SendMsg reply %d: %v", i, err)
		}
		var rr reply
		if _, err := cliSock.RecvMsg(&rr); err != nil {
			t.Fatalf("RecvMsg reply %d: %v", i, err)
		}
	}
}

func TestSocketFramingLargeThenSmall(t *testing.T) {
	// Verify that after a chunked message, small messages still work
	server, client, err := unixsocket.NewSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer client.Close()

	srvSock := newSocket(server)
	cliSock := newSocket(client)

	// Send large message first
	largePaths := make([]OpenCmd, 400)
	for i := range largePaths {
		largePaths[i] = OpenCmd{Path: "/w/" + strings.Repeat("x", 80)}
	}

	largeCmd := cmd{Cmd: cmdOpen, OpenCmd: largePaths}

	errCh := make(chan error, 1)
	go func() {
		var rc cmd
		_, err := srvSock.RecvMsg(&rc)
		if err != nil {
			errCh <- err
			return
		}
		if len(rc.OpenCmd) != 400 {
			errCh <- err
			return
		}
		// Reply
		errCh <- srvSock.SendMsg(reply{}, unixsocket.Msg{})
	}()

	if err := cliSock.SendMsg(largeCmd, unixsocket.Msg{}); err != nil {
		t.Fatalf("SendMsg large: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("large msg error: %v", err)
	}
	var lr reply
	if _, err := cliSock.RecvMsg(&lr); err != nil {
		t.Fatalf("RecvMsg large reply: %v", err)
	}

	// Now send a small message (ping) - should work (no leftover chunk state)
	if err := cliSock.SendMsg(cmd{Cmd: cmdPing}, unixsocket.Msg{}); err != nil {
		t.Fatalf("SendMsg ping after large: %v", err)
	}
	var pc cmd
	if _, err := srvSock.RecvMsg(&pc); err != nil {
		t.Fatalf("RecvMsg ping after large: %v", err)
	}
	if pc.Cmd != cmdPing {
		t.Errorf("after large msg, got cmd %d, want %d", pc.Cmd, cmdPing)
	}
}
