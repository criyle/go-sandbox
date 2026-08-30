package ptracer

import (
	"testing"
	"time"

	"github.com/criyle/go-sandbox/runner"
	"golang.org/x/sys/unix"
)

func TestClenDoesNotExceedBuffer(t *testing.T) {
	if got := clen([]byte("unterminated")); got != len("unterminated") {
		t.Fatalf("clen returned %d, want %d", got, len("unterminated"))
	}
}

func TestCheckUsageTracksProcessPeaks(t *testing.T) {
	tracer := &Tracer{Limit: runner.Limit{TimeLimit: time.Second, MemoryLimit: 10 << 20}}
	ph := newPtraceHandle(tracer, 100)

	var first unix.Rusage
	first.Utime.Sec = 0
	first.Utime.Usec = 500000
	first.Maxrss = 4096
	ph.checkUsage(100, first)

	var second unix.Rusage
	second.Utime.Sec = 0
	second.Utime.Usec = 600000
	second.Maxrss = 4096
	ph.checkUsage(101, second)

	if want := time.Second + 100*time.Millisecond; ph.userTime != want {
		t.Fatalf("aggregated CPU time = %v, want %v", ph.userTime, want)
	}
	if want := runner.Size(4 << 20); ph.memory != want {
		t.Fatalf("aggregated memory = %d, want %d", ph.memory, want)
	}
}
