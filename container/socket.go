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

type socket struct {
	*unixsocket.Socket

	recvBuff bytes.Buffer
	decoder  *gob.Decoder

	sendBuff bytes.Buffer
	encoder  *gob.Encoder
}

func newSocket(s *unixsocket.Socket) *socket {
	soc := socket{
		Socket: s,
	}
	soc.decoder = gob.NewDecoder(&soc.recvBuff)
	soc.encoder = gob.NewEncoder(&soc.sendBuff)

	return &soc
}

func (s *socket) RecvMsg(e interface{}) (*unixsocket.Msg, error) {
	buff := bufferPool.Get().([]byte)
	defer bufferPool.Put(buff)

	n, msg, err := s.Socket.RecvMsg(buff)
	if err != nil {
		return nil, fmt.Errorf("RecvMsg: %v", err)
	}
	s.recvBuff.Reset()
	s.recvBuff.Write(buff[:n])

	if err := s.decoder.Decode(e); err != nil {
		return nil, fmt.Errorf("RecvMsg: failed to decode %v", err)
	}
	return msg, nil
}

func (s *socket) SendMsg(e interface{}, msg *unixsocket.Msg) error {
	s.sendBuff.Reset()
	if err := s.encoder.Encode(e); err != nil {
		return fmt.Errorf("SendMsg: failed to encode %v", err)
	}

	if err := s.Socket.SendMsg(s.sendBuff.Bytes(), msg); err != nil {
		return fmt.Errorf("SendMsg: failed to SendMsg %v", err)
	}
	return nil
}
