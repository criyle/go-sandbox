package seccomp

import "testing"

func TestSockFprogEmpty(t *testing.T) {
	if got := (Filter(nil)).SockFprog(); got != nil {
		t.Fatalf("SockFprog() = %#v, want nil for an empty filter", got)
	}
}
