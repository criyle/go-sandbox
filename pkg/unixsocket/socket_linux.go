// Package unixsocket provides wrapper for Linux unix socket to send and recv oob messages
// including fd and user credential.
package unixsocket

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"syscall"
)

// oob size default to page size
const oobSize = 4 << 10 // 4kb

// Socket wrappers a unix socket connection
type Socket struct {
	*net.UnixConn
	sendBuff []byte
	recvBuff []byte
}

// Msg is the oob msg with the message
type Msg struct {
	Fds  []int          // unix rights
	Cred *syscall.Ucred // unix credential
}

func newSocket(conn *net.UnixConn) *Socket {
	return &Socket{
		UnixConn: conn,
		sendBuff: make([]byte, oobSize),
		recvBuff: make([]byte, oobSize),
	}
}

// NewSocket creates Socket conn struct using existing unix socket fd
// creates by socketpair or net.DialUnix and mark it as close_on_exec (avoid fd leak)
// it need SOCK_SEQPACKET socket for reliable transfer
// it will need SO_PASSCRED to pass unix credential, Notice: in the documentation,
// if cred is not specified, self information will be sent
func NewSocket(fd int) (*Socket, error) {
	syscall.SetNonblock(fd, true)
	syscall.CloseOnExec(fd)

	file := os.NewFile(uintptr(fd), "unix-socket")
	if file == nil {
		return nil, fmt.Errorf("NewSocket: %d is not a valid fd", fd)
	}
	defer file.Close()

	conn, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("NewSocket: %d is not a valid unix socket connection", fd)
	}
	return newSocket(unixConn), nil
}

// NewSocketPair creates connected unix socketpair using SOCK_SEQPACKET
func NewSocketPair() (*Socket, *Socket, error) {
	fd, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("NewSocketPair: failed to call socketpair %v", err)
	}

	ins, err := NewSocket(fd[0])
	if err != nil {
		syscall.Close(fd[0])
		syscall.Close(fd[1])
		return nil, nil, fmt.Errorf("NewSocketPair: failed to call NewSocket on sender %v", err)
	}

	outs, err := NewSocket(fd[1])
	if err != nil {
		ins.Close()
		syscall.Close(fd[1])
		return nil, nil, fmt.Errorf("NewSocketPair: failed to call NewSocket receiver %v", err)
	}

	return ins, outs, nil
}

// SetPassCred set sockopt for pass cred for unix socket
func (s *Socket) SetPassCred(option int) error {
	sysconn, err := s.SyscallConn()
	if err != nil {
		return err
	}
	return sysconn.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PASSCRED, option)
	})
}

// SendMsg sendmsg to unix socket and encode possible unix right / credential
func (s *Socket) SendMsg(b []byte, m Msg) error {
	oob := bytes.NewBuffer(s.sendBuff[:0])
	if len(m.Fds) > 0 {
		oob.Write(syscall.UnixRights(m.Fds...))
	}
	if m.Cred != nil {
		oob.Write(syscall.UnixCredentials(m.Cred))
	}

	_, _, err := s.WriteMsgUnix(b, oob.Bytes(), nil)
	if err != nil {
		return err
	}
	return nil
}

// RecvMsg recvmsg from unix socket and parse possible unix right / credential
func (s *Socket) RecvMsg(b []byte) (int, Msg, error) {
	var msg Msg
	n, oobn, _, _, err := s.ReadMsgUnix(b, s.recvBuff)
	if err != nil {
		return 0, msg, err
	}
	// parse oob msg
	msgs, err := syscall.ParseSocketControlMessage(s.recvBuff[:oobn])
	if err != nil {
		return 0, msg, err
	}
	msg, err = parseMsg(msgs)
	if err != nil {
		return 0, msg, err
	}
	return n, msg, nil
}

func parseMsg(msgs []syscall.SocketControlMessage) (msg Msg, err error) {
	defer func() {
		if err != nil {
			for _, f := range msg.Fds {
				syscall.Close(f)
			}
			msg.Fds = nil
		}
	}()
	for _, m := range msgs {
		if m.Header.Level != syscall.SOL_SOCKET {
			continue
		}

		switch m.Header.Type {
		case syscall.SCM_CREDENTIALS:
			cred, err := syscall.ParseUnixCredentials(&m)
			if err != nil {
				return msg, err
			}
			msg.Cred = cred

		case syscall.SCM_RIGHTS:
			fds, err := syscall.ParseUnixRights(&m)
			if err != nil {
				return msg, err
			}
			msg.Fds = fds
		}
	}
	return msg, nil
}
