package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

// benchDrainBuffer is large enough to receive any single datagram sent by the
// benchmarks below (largest payload is ~128KB) plus headroom.
const benchDrainBuffer = 256 << 10

// BenchmarkSocketPing measures a full ping round-trip (small message hot path).
func BenchmarkSocketPing(b *testing.B) {
	server, client, err := unixsocket.NewSocketPair()
	if err != nil {
		b.Fatal(err)
	}
	defer server.Close()
	defer client.Close()

	srv := newSocket(server)
	cli := newSocket(client)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			var in cmd
			if _, err := srv.RecvMsg(&in); err != nil {
				return
			}
			if err := srv.SendMsg(reply{}, unixsocket.Msg{}); err != nil {
				return
			}
		}
	}()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := cli.SendMsg(cmd{Cmd: cmdPing}, unixsocket.Msg{}); err != nil {
			b.Fatal(err)
		}
		var out reply
		if _, err := cli.RecvMsg(&out); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	server.Close()
	<-done
}

// BenchmarkSocketSendSmall measures send+gob-encode cost for a tiny message
// with a fast kernel-level drain. This represents the hot-path cost, which
// should stay identical to the pre-framing baseline (small messages are sent
// as-is with no chunk header).
func BenchmarkSocketSendSmall(b *testing.B) {
	server, client, err := unixsocket.NewSocketPair()
	if err != nil {
		b.Fatal(err)
	}
	defer server.Close()
	defer client.Close()

	cli := newSocket(client)

	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, benchDrainBuffer)
		close(ready)
		for {
			_, _, err := server.RecvMsg(buf)
			if err != nil {
				return
			}
		}
	}()
	<-ready

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := cli.SendMsg(cmd{Cmd: cmdPing}, unixsocket.Msg{}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	server.Close()
	<-done
}

// BenchmarkSocketSendLarge measures send cost for messages of increasing size,
// including those that cross the 32KB buffer boundary and are split into chunks.
func BenchmarkSocketSendLarge(b *testing.B) {
	sizes := []struct {
		name    string
		paths   int
		pathLen int
	}{
		{"tiny_10paths", 10, 50}, // well under 32KB, single datagram, no chunks
		{"near_32KB", 200, 140},  // ~32KB gob, near boundary
		{"64KB", 400, 140},       // split into chunks
		{"128KB", 800, 140},      // split into chunks
	}

	for _, tc := range sizes {
		b.Run(tc.name, func(b *testing.B) {
			server, client, err := unixsocket.NewSocketPair()
			if err != nil {
				b.Fatal(err)
			}
			defer server.Close()
			defer client.Close()

			cli := newSocket(client)

			paths := make([]OpenCmd, tc.paths)
			for i := range paths {
				paths[i] = OpenCmd{
					Path: "/tmp/" + strings.Repeat("p", tc.pathLen) + fmt.Sprintf("_%d", i),
				}
			}
			sendCmd := cmd{Cmd: cmdOpen, OpenCmd: paths}

			ready := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, benchDrainBuffer)
				close(ready)
				for {
					_, _, err := server.RecvMsg(buf)
					if err != nil {
						return
					}
				}
			}()
			<-ready

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := cli.SendMsg(sendCmd, unixsocket.Msg{}); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			server.Close()
			<-done
		})
	}
}

// BenchmarkSocketOpenRoundTrip measures end-to-end open round-trip with real
// files and FD passing across the socket. Exercises both gob encoding size
// and FD batch limits (SCM_MAX_FD=253).
func BenchmarkSocketOpenRoundTrip(b *testing.B) {
	tmpDir := b.TempDir()
	for _, n := range []int{10, 100, 200, 500} {
		b.Run(fmt.Sprintf("%d_files", n), func(b *testing.B) {
			dir := filepath.Join(tmpDir, fmt.Sprintf("n%d", n))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				b.Fatal(err)
			}
			args := make([]OpenCmd, n)
			for j := 0; j < n; j++ {
				p := filepath.Join(dir, fmt.Sprintf("f%d", j))
				if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
					b.Fatal(err)
				}
				args[j] = OpenCmd{Path: p, Flag: os.O_RDONLY, Perm: 0}
			}

			server, client, err := unixsocket.NewSocketPair()
			if err != nil {
				b.Fatal(err)
			}
			defer server.Close()
			defer client.Close()
			srv := newSocket(server)
			cli := newSocket(client)

			serveDone := make(chan struct{})
			go func() {
				defer close(serveDone)
				for {
					var in cmd
					msg, err := srv.RecvMsg(&in)
					if err != nil {
						return
					}
					fds := make([]int, 0, len(in.OpenCmd))
					closeFds(msg.Fds)
					for _, o := range in.OpenCmd {
						f, e := os.OpenFile(o.Path, o.Flag, o.Perm)
						if e != nil {
							continue
						}
						fds = append(fds, int(f.Fd()))
					}
					_ = srv.SendMsg(reply{}, unixsocket.Msg{Fds: fds})
				}
			}()

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := cli.SendMsg(cmd{Cmd: cmdOpen, OpenCmd: args}, unixsocket.Msg{}); err != nil {
					b.Fatal(err)
				}
				var r reply
				recvMsg, err := cli.RecvMsg(&r)
				if err != nil {
					b.Fatal(err)
				}
				closeFds(recvMsg.Fds)
			}
			b.StopTimer()
			server.Close()
			<-serveDone
		})
	}
}
