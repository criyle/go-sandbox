package container

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

// Ping send ping message to container, wait for 3 second before timeout
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
	if err := c.sendCmd(cmd, unixsocket.Msg{}); err != nil {
		return fmt.Errorf("ping: %w", err)
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
	if err := c.sendCmd(cmd, unixsocket.Msg{}); err != nil {
		return fmt.Errorf("conf: %w", err)
	}
	return c.recvAckReply("conf")
}

// Open open files in container
func (c *container) Open(p []OpenCmd) ([]OpenCmdResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()

	// send copyin
	cmd := cmd{
		Cmd:     cmdOpen,
		OpenCmd: p,
	}
	if err := c.sendCmd(cmd, unixsocket.Msg{}); err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	reply, msg, err := c.recvReply()
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	results := make([]OpenCmdResult, len(p))
	fdIndex := 0
	for i, errStr := range reply.OpenErrors {
		if errStr != "" {
			// This specific file failed to open
			results[i] = OpenCmdResult{Err: errors.New(errStr)}
			continue
		}
		if fdIndex >= len(msg.Fds) {
			closeFds(msg.Fds)
			return nil, fmt.Errorf("open: mismatch between success flags and received FDs")
		}
		fd := msg.Fds[fdIndex]
		syscall.CloseOnExec(fd)
		f := os.NewFile(uintptr(fd), p[i].Path)
		if f == nil {
			closeFds(msg.Fds[fdIndex:])
			return nil, fmt.Errorf("open: failed to create file for fd: %d", fd)
		}
		results[i] = OpenCmdResult{File: f}
		fdIndex++
	}
	return results, nil
}

func (c *container) Symlink(l []SymbolicLink) []error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cmd := cmd{
		Cmd:        cmdSymlink,
		SymlinkCmd: l,
	}

	if err := c.sendCmd(cmd, unixsocket.Msg{}); err != nil {
		// If transport fails, we return the error for all entries or a wrap
		return []error{fmt.Errorf("symlink transport: %w", err)}
	}

	reply, _, err := c.recvReply()
	if err != nil {
		return []error{fmt.Errorf("symlink recv: %w", err)}
	}

	results := make([]error, len(l))
	// Map error strings back to error objects
	for i, errStr := range reply.OpenErrors {
		if errStr != "" {
			results[i] = errors.New(errStr)
		} else {
			results[i] = nil // Success
		}
	}
	return results
}

// Delete remove file from container
func (c *container) Delete(p string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cmd := cmd{
		Cmd:       cmdDelete,
		DeleteCmd: &deleteCmd{Path: p},
	}
	if err := c.sendCmd(cmd, unixsocket.Msg{}); err != nil {
		return fmt.Errorf("delete: %w", err)
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
	if err := c.sendCmd(cmd, unixsocket.Msg{}); err != nil {
		return fmt.Errorf("reset: %w", err)
	}
	return c.recvAckReply("reset")
}
