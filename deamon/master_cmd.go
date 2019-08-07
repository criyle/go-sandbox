package deamon

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/criyle/go-judger/unixsocket"
)

// Ping send ping message to container
func (m *Master) Ping() error {
	// send ping
	cmd := Cmd{
		Cmd: cmdPing,
	}
	if err := m.sendCmd(&cmd, nil); err != nil {
		return fmt.Errorf("ping: %v", err)
	}
	// receive no error
	reply, _, err := m.recvReply()
	if err != nil {
		return fmt.Errorf("ping: %v", err)
	}
	if reply.Error != "" {
		return fmt.Errorf("ping: reply error(%v)", reply.Error)
	}
	return nil
}

func (m *Master) recvReply() (*Reply, *unixsocket.Msg, error) {
	var reply Reply
	buff := GetBuffer()
	defer PutBuffer(buff)
	n, msg, err := m.socket.RecvMsg(buff)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to RecvMsg(%v)", err)
	}
	dec := gob.NewDecoder(bytes.NewReader(buff[:n]))
	if err := dec.Decode(&reply); err != nil {
		return nil, nil, fmt.Errorf("failed to decode(%v)", err)
	}
	return &reply, msg, nil
}

func (m *Master) sendCmd(cmd *Cmd, msg *unixsocket.Msg) error {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	if err := enc.Encode(cmd); err != nil {
		return fmt.Errorf("failed to encode(%v)", err)
	}
	if err := m.socket.SendMsg(buff.Bytes(), msg); err != nil {
		return fmt.Errorf("failed to SendMsg(%v)", err)
	}
	return nil
}
