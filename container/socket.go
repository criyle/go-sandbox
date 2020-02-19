package container

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"sync"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

// 16k buffsize
const bufferSize = 16 << 10

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, bufferSize)
	},
}

type socket unixsocket.Socket

func (s *socket) RecvMsg(e interface{}) (*unixsocket.Msg, error) {
	soc := (*unixsocket.Socket)(s)

	buff := bufferPool.Get().([]byte)
	defer bufferPool.Put(buff)

	n, msg, err := soc.RecvMsg(buff)
	if err != nil {
		return nil, fmt.Errorf("RecvMsg: %v", err)
	}

	if err := gob.NewDecoder(bytes.NewReader(buff[:n])).Decode(e); err != nil {
		return nil, fmt.Errorf("RecvMsg: failed to decode %w", err)
	}
	return msg, nil
}

func (s *socket) SendMsg(e interface{}, msg *unixsocket.Msg) error {
	soc := (*unixsocket.Socket)(s)

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	// use buf pool to reduce allocation
	buff := bytes.NewBuffer(buf[:0])
	if err := gob.NewEncoder(buff).Encode(e); err != nil {
		return fmt.Errorf("SendMsg: failed to encode %w", err)
	}

	if err := soc.SendMsg(buff.Bytes(), msg); err != nil {
		return fmt.Errorf("SendMsg: failed to SendMsg %w", err)
	}
	return nil
}
