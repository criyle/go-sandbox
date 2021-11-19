package unixsocket

import (
	"bytes"
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
