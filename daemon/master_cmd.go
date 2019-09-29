package daemon

import (
	"fmt"
	"os"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
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
	if len(msg.Fds) != 1 {
		closeFds(msg.Fds)
		return nil, fmt.Errorf("open: unexpected number of fd %v", len(msg.Fds))
	}
	f := os.NewFile(uintptr(msg.Fds[0]), p)
	if f == nil {
		closeFds(msg.Fds)
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
		return fmt.Errorf("%v: recvAck %v", name, err)
	}
	if reply.Error != "" {
		return fmt.Errorf("%v: container error %v", name, reply.Error)
	}
	return nil
}

func (m *Master) recvReply() (*Reply, *unixsocket.Msg, error) {
	reply := new(Reply)
	msg, err := (*socket)(m.socket).RecvMsg(reply)
	if err != nil {
		return nil, nil, err
	}
	return reply, msg, nil
}

func (m *Master) sendCmd(cmd *Cmd, msg *unixsocket.Msg) error {
	return (*socket)(m.socket).SendMsg(cmd, msg)
}
