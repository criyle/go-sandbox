package container

import (
	"fmt"
	"os"
	"time"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

// Ping send ping message to container
func (c *container) Ping() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// avoid infinite wait (max 3s)
	const pingWait = 3 * time.Second
	c.socket.SetDeadline(time.Now().Add(pingWait))
	defer c.socket.SetDeadline(time.Time{})

	// send ping
	cmd := cmd{
		Cmd: cmdPing,
	}
	if err := c.sendCmd(&cmd, nil); err != nil {
		return fmt.Errorf("ping: %v", err)
	}
	// receive no error
	return c.recvAckReply("ping")
}

// conf send configuration to container (used by builder only)
func (c *container) conf(conf *containerConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cmd := cmd{
		Cmd:     cmdConf,
		ConfCmd: &confCmd{Conf: *conf},
	}
	if err := c.sendCmd(&cmd, nil); err != nil {
		return fmt.Errorf("conf: %v", err)
	}
	return c.recvAckReply("conf")
}

// Open open files in container
func (c *container) Open(p []OpenCmd) ([]*os.File, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// send copyin
	cmd := cmd{
		Cmd:     cmdOpen,
		OpenCmd: p,
	}
	if err := c.sendCmd(&cmd, nil); err != nil {
		return nil, fmt.Errorf("open: %v", err)
	}
	reply, msg, err := c.recvReply()
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
			return nil, fmt.Errorf("open: failed NewFile %v", fd)
		}
		ret = append(ret, f)
	}
	return ret, nil
}

// Delete remove file from container
func (c *container) Delete(p string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cmd := cmd{
		Cmd:       cmdDelete,
		DeleteCmd: &deleteCmd{Path: p},
	}
	if err := c.sendCmd(&cmd, nil); err != nil {
		return fmt.Errorf("delete: %v", err)
	}
	return c.recvAckReply("delete")
}

// Reset remove all from /tmp and /w
func (c *container) Reset() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cmd := cmd{
		Cmd: cmdReset,
	}
	if err := c.sendCmd(&cmd, nil); err != nil {
		return fmt.Errorf("reset: %v", err)
	}
	return c.recvAckReply("reset")
}

func (c *container) recvAckReply(name string) error {
	reply, _, err := c.recvReply()
	if err != nil {
		return fmt.Errorf("%v: recvAck %v", name, err)
	}
	if reply.Error != nil {
		return fmt.Errorf("%v: container error %v", name, reply.Error)
	}
	return nil
}

func (c *container) recvReply() (*reply, *unixsocket.Msg, error) {
	reply := new(reply)
	msg, err := c.socket.RecvMsg(reply)
	if err != nil {
		return nil, nil, err
	}
	return reply, msg, nil
}

func (c *container) sendCmd(cmd *cmd, msg *unixsocket.Msg) error {
	return c.socket.SendMsg(cmd, msg)
}
