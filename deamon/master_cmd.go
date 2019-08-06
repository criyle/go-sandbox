package deamon

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

// Ping send ping message to container
func (m *Master) Ping() error {
	var (
		wbuff bytes.Buffer
		reply Reply
	)
	rbuff := GetBuffer()
	defer PutBuffer(rbuff)
	// send ping
	enc := gob.NewEncoder(&wbuff)
	cmd := Cmd{
		Cmd: cmdPing,
	}
	if err := enc.Encode(cmd); err != nil {
		return fmt.Errorf("ping: failed to encode(%v)", err)
	}
	if err := m.socket.SendMsg(wbuff.Bytes(), nil); err != nil {
		return fmt.Errorf("ping: failed to sendMsg(%v)", err)
	}
	// receive no error
	n, _, err := m.socket.RecvMsg(rbuff)
	if err != nil {
		return fmt.Errorf("ping: failed to recvMsg(%v)", err)
	}
	dec := gob.NewDecoder(bytes.NewReader(rbuff[:n]))
	if err := dec.Decode(&reply); err != nil {
		return fmt.Errorf("ping: failed to decode(%v)", err)
	}
	if reply.Error != "" {
		return fmt.Errorf("ping: reply error(%v)", reply.Error)
	}
	return nil
}
