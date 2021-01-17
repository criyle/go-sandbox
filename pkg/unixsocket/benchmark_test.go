package unixsocket

import "testing"

func BenchmarkBaseline(b *testing.B) {
	s, t, err := NewSocketPair()
	if err != nil {
		b.Fatal(err)
	}
	m := make([]byte, 1024)
	b.ResetTimer()
	go func() {
		msg := []byte("message")
		for i := 0; i < b.N; i++ {
			s.SendMsg(msg, nil)
		}
	}()

	for i := 0; i < b.N; i++ {
		t.RecvMsg(m)
	}
}

func BenchmarkGoroutine(b *testing.B) {
	s, t, err := NewSocketPair()
	if err != nil {
		b.Fatal(err)
	}
	m := make([]byte, 1024)
	b.ResetTimer()
	go func() {
		msg := []byte("message")
		for i := 0; i < b.N; i++ {
			s.SendMsg(msg, nil)
		}
	}()

	for i := 0; i < b.N; i++ {
		c := make(chan struct{})
		go func() {
			defer close(c)
			t.RecvMsg(m)
		}()
		<-c
	}
}

func BenchmarkChannel(b *testing.B) {
	c := make(chan []byte)
	benchGoroutine(b, c)
}

func BenchmarkChannelBuffed(b *testing.B) {
	c := make(chan []byte, 1)
	benchGoroutine(b, c)
}

func BenchmarkChannelBuffed4(b *testing.B) {
	c := make(chan []byte, 4)
	benchGoroutine(b, c)
}

func BenchmarkEmptyGoroutine(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c := make(chan struct{})
		go func() {
			close(c)
		}()
		<-c
	}
}

func benchGoroutine(b *testing.B, c chan []byte) {
	s, t, err := NewSocketPair()
	if err != nil {
		b.Fatal(err)
	}

	go func() {
		msg := []byte("message")
		for i := 0; i < b.N; i++ {
			s.SendMsg(msg, nil)
		}
	}()

	b.ResetTimer()
	go func() {
		m := make([]byte, 1024)
		for i := 0; i < b.N; i++ {
			t.RecvMsg(m)
			c <- m
		}
	}()

	for i := 0; i < b.N; i++ {
		<-c
	}
}
