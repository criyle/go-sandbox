package daemon

import (
	"fmt"
	"os"
	"time"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

// Ping send ping message to container
func (m *Master) Ping() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// avoid infinite wait (max 3s)
	const pingWait = 3 * time.Second
	m.socket.SetDeadline(time.Now().Add(pingWait))
	defer m.socket.SetDeadline(time.Time{})

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

// conf send configuration to container (used by builder only)
func (m *Master) conf(conf *containerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cmd := Cmd{
		Cmd:     cmdConf,
		ConfCmd: &ConfCmd{Conf: *conf},
	}
	if err := m.sendCmd(&cmd, nil); err != nil {
		return fmt.Errorf("conf: %v", err)
	}
	return m.recvAckReply("conf")
}

// Open open files in container
func (m *Master) Open(p []OpenCmd) ([]*os.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// send copyin
	cmd := Cmd{
		Cmd:     cmdOpen,
		OpenCmd: p,
	}
	if err := m.sendCmd(&cmd, nil); err != nil {
		return nil, fmt.Errorf("open: %v", err)
	}
	reply, msg, err := m.recvReply()
	if err != nil {
		return nil, fmt.Errorf("open: %v", err)
	}
	if reply.Error != nil {
		return nil, fmt.Errorf("open: %v", reply.Error)
	}
	if len(msg.Fds) != len(p) {
		closeFds(msg.Fds)
		return nil, fmt.Errorf("open: unexpected number of fd %v / %v", len(msg.Fds), len(p))
	}

	ret := make([]*os.File, 0, len(p))
	for i, fd := range msg.Fds {
		f := os.NewFile(uintptr(fd), p[i].Path)
		if f == nil {
			closeFds(msg.Fds)
			return nil, fmt.Errorf("open: failed %v", msg.Fds[0])
		}
		ret = append(ret, f)
	}
	return ret, nil
}

// Delete remove file from container
func (m *Master) Delete(p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cmd := Cmd{
		Cmd:       cmdDelete,
		DeleteCmd: &DeleteCmd{Path: p},
	}
	if err := m.sendCmd(&cmd, nil); err != nil {
		return fmt.Errorf("delete: %v", err)
	}
	return m.recvAckReply("delete")
}

// Reset remove all from /tmp and /w
func (m *Master) Reset() error {
	m.mu.Lock()
	defer m.mu.Unlock()

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
	if reply.Error != nil {
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
