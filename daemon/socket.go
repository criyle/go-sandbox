package daemon

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

type socket unixsocket.Socket

func (s *socket) RecvMsg(e interface{}) (*unixsocket.Msg, error) {
	soc := (*unixsocket.Socket)(s)
	buff := GetBuffer()
	defer PutBuffer(buff)

	n, msg, err := soc.RecvMsg(buff)
	if err != nil {
		return nil, fmt.Errorf("RecvMsg: %v", err)
	}

	if err := gob.NewDecoder(bytes.NewReader(buff[:n])).Decode(e); err != nil {
		return nil, fmt.Errorf("RecvMsg: failed to decode %v", err)
	}
	return msg, nil
}

func (s *socket) SendMsg(e interface{}, msg *unixsocket.Msg) error {
	soc := (*unixsocket.Socket)(s)
	buf := GetBuffer()
	defer PutBuffer(buf)

	// use buf pool to reduce allocation
	buff := bytes.NewBuffer(buf[:0])
	if err := gob.NewEncoder(buff).Encode(e); err != nil {
		return fmt.Errorf("SendMsg: failed to encode %v", err)
	}

	if err := soc.SendMsg(buff.Bytes(), msg); err != nil {
		return fmt.Errorf("SendMsg: failed to SendMsg %v", err)
	}
	return nil
}
