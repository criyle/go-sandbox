package container

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

// maxOpenPerBatch limits the number of files opened in a single batch to stay
// under the Linux SCM_MAX_FD (253) kernel limit for sendmsg SCM_RIGHTS.
// 200 leaves a safe margin.
const maxOpenPerBatch = 200

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
func (c *container) Open(p []OpenCmd) (results []OpenCmdResult, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()

	var opened []*os.File
	defer func() {
		if err != nil {
			for _, f := range opened {
				f.Close()
			}
		}
	}()

	// send copyin in batches to stay under the SCM_MAX_FD kernel limit
	results = make([]OpenCmdResult, len(p))
	for offset := 0; offset < len(p); offset += maxOpenPerBatch {
		end := offset + maxOpenPerBatch
		if end > len(p) {
			end = len(p)
		}
		cmd := cmd{
			Cmd:     cmdOpen,
			OpenCmd: p[offset:end],
		}
		if err := c.sendCmd(cmd, unixsocket.Msg{}); err != nil {
			return results, fmt.Errorf("open: %w", err)
		}
		reply, msg, err := c.recvReply()
		if err != nil {
			return results, fmt.Errorf("open: %w", err)
		}
		if reply.Error != nil {
			closeFds(msg.Fds)
			return results, fmt.Errorf("open: container error: %v", reply.Error)
		}
		if len(reply.BatchErrors) != end-offset {
			closeFds(msg.Fds)
			return results, fmt.Errorf("open: response length mismatch: got %d, want %d", len(reply.BatchErrors), end-offset)
		}

		fdIndex := 0
		for i, errStr := range reply.BatchErrors {
			if errStr != "" {
				// This specific file failed to open
				results[offset+i] = OpenCmdResult{Err: errors.New(errStr)}
				continue
			}
			if fdIndex >= len(msg.Fds) {
				closeFds(msg.Fds[fdIndex:])
				return results, fmt.Errorf("open: mismatch between success flags and received FDs")
			}
			fd := msg.Fds[fdIndex]
			fdIndex++
			syscall.CloseOnExec(fd)
			f := os.NewFile(uintptr(fd), p[offset+i].Path)
			if f == nil {
				closeFds([]int{fd})
				closeFds(msg.Fds[fdIndex:])
				return results, fmt.Errorf("open: failed to create file for fd: %d", fd)
			}
			opened = append(opened, f)
			results[offset+i] = OpenCmdResult{File: f}
		}
		if fdIndex != len(msg.Fds) {
			closeFds(msg.Fds[fdIndex:])
			return results, fmt.Errorf("open: mismatch between success flags and received FDs")
		}
	}
	return results, nil
}

func (c *container) Symlink(l []SymbolicLink) ([]error, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cmd := cmd{
		Cmd:        cmdSymlink,
		SymlinkCmd: l,
	}

	if err := c.sendCmd(cmd, unixsocket.Msg{}); err != nil {
		// If transport fails, we return the error for all entries or a wrap
		return nil, fmt.Errorf("symlink transport: %w", err)
	}

	reply, _, err := c.recvReply()
	if err != nil {
		return nil, fmt.Errorf("symlink recv: %w", err)
	}
	if reply.Error != nil {
		return nil, fmt.Errorf("symlink: container error: %v", reply.Error)
	}
	if len(reply.BatchErrors) != len(l) {
		return nil, fmt.Errorf("symlink: response length mismatch: got %d, want %d", len(reply.BatchErrors), len(l))
	}

	results := make([]error, len(l))
	// Map error strings back to error objects
	for i, errStr := range reply.BatchErrors {
		if errStr != "" {
			results[i] = errors.New(errStr)
		} else {
			results[i] = nil // Success
		}
	}
	return results, nil
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
