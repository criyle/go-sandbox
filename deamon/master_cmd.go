package deamon

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"

	"github.com/criyle/go-sandbox/unixsocket"
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
	return m.recvAckReply("ping")
}

// CopyIn copies file to container
func (m *Master) CopyIn(f *os.File, p string) error {
	// send copyin
	cmd := Cmd{
		Cmd:  cmdCopyIn,
		Path: p,
	}
	msg := unixsocket.Msg{
		Fds: []int{int(f.Fd())},
	}
	if err := m.sendCmd(&cmd, &msg); err != nil {
		return fmt.Errorf("copyin: %v", err)
	}
	return m.recvAckReply("copyin")
}

// Open open file in container
func (m *Master) Open(p string) (*os.File, error) {
	// send copyin
	cmd := Cmd{
		Cmd:  cmdOpen,
		Path: p,
	}
	if err := m.sendCmd(&cmd, nil); err != nil {
		return nil, fmt.Errorf("open: %v", err)
	}
	reply, msg, err := m.recvReply()
	if err != nil {
		return nil, fmt.Errorf("open: %v", err)
	}
	if reply.Error != "" {
		return nil, fmt.Errorf("open: %v", reply.Error)
	}
	if len(msg.Fds) == 0 {
		return nil, fmt.Errorf("open: did not receive fd")
	}
	f := os.NewFile(uintptr(msg.Fds[0]), p)
	if f == nil {
		return nil, fmt.Errorf("open: failed %v", msg.Fds[0])
	}
	return f, nil
}

// Delete remove file from container
func (m *Master) Delete(p string) error {
	cmd := Cmd{
		Cmd:  cmdDelete,
		Path: p,
	}
	if err := m.sendCmd(&cmd, nil); err != nil {
		return fmt.Errorf("delete: %v", err)
	}
	return m.recvAckReply("delete")
}

// Reset remove all from /tmp and /w
func (m *Master) Reset() error {
	cmd := Cmd{
		Cmd: cmdReset,
	}
	if err := m.sendCmd(&cmd, nil); err != nil {
		return fmt.Errorf("reset: %v", err)
	}
	return m.recvAckReply("reset")
}

func (m *Master) recvAckReply(name string) error {
	reply, _, err := m.recvReply()
	if err != nil {
		return fmt.Errorf(name+": %v", err)
	}
	if reply.Error != "" {
		return fmt.Errorf(name+": %v", reply.Error)
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
	if err := gob.NewDecoder(bytes.NewReader(buff[:n])).Decode(&reply); err != nil {
		return nil, nil, fmt.Errorf("failed to decode(%v)", err)
	}
	return &reply, msg, nil
}

func (m *Master) sendCmd(cmd *Cmd, msg *unixsocket.Msg) error {
	var buff bytes.Buffer
	if err := gob.NewEncoder(&buff).Encode(cmd); err != nil {
		return fmt.Errorf("failed to encode(%v)", err)
	}
	if err := m.socket.SendMsg(buff.Bytes(), msg); err != nil {
		return fmt.Errorf("failed to SendMsg(%v)", err)
	}
	return nil
}
