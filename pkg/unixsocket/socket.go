package unixsocket

import (
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
)

// oob size default to page size
const oobSize = 4096

// use pool to avoid allocate
var oobPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, oobSize)
	},
}

// Socket represents a unix socket
type Socket struct {
	*net.UnixConn
}

// Msg is the oob msg with the message
type Msg struct {
	Fds  []int          // unix rights
	Cred *syscall.Ucred // unix credential
}

// NewSocket creates Socket conn struct using existing unix socket fd
// creates by socketpair or net.DialUnix and mark it as close_on_exec (avoid fd leak)
// it need SOCK_SEQPACKET socket for reliable transfer
// it will need SO_PASSCRED to pass unix credential, Notice: in the documentation,
// if cred is not specified, self information will be sent
func NewSocket(fd int) (*Socket, error) {
	file := os.NewFile(uintptr(fd), "unix-socket")
	if file == nil {
		return nil, fmt.Errorf("NewSocket: fd(%d) is not a valid fd", fd)
	}
	defer file.Close()
	syscall.CloseOnExec(int(file.Fd()))
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("NewSocket: fd(%d) is not a unix socket", fd)
	}
	return &Socket{unixConn}, nil
}

// NewSocketPair creates connected unix socketpair using SOCK_SEQPACKET
func NewSocketPair() (*Socket, *Socket, error) {
	fd, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("NewSocketPair: failed to call socketpair(%v)", err)
	}
	ins, err := NewSocket(fd[0])
	if err != nil {
		syscall.Close(fd[0])
		syscall.Close(fd[1])
		return nil, nil, fmt.Errorf("NewSocketPair: failed to call NewSocket ins(%v)", err)
	}
	outs, err := NewSocket(fd[1])
	if err != nil {
		ins.Close()
		syscall.Close(fd[1])
		return nil, nil, fmt.Errorf("NewSocketPair: failed to call NewSocket outs(%v)", err)
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
func (s *Socket) SendMsg(b []byte, m *Msg) error {
	var oob []byte
	if m != nil {
		if len(m.Fds) > 0 {
			oob = append(oob, syscall.UnixRights(m.Fds...)...)
		}
		if m.Cred != nil {
			oob = append(oob, syscall.UnixCredentials(m.Cred)...)
		}
	}
	_, _, err := s.WriteMsgUnix(b, oob, nil)
	if err != nil {
		return err
	}
	return nil
}

// RecvMsg recvmsg from unix socket and parse possible unix right / credential
func (s *Socket) RecvMsg(b []byte) (int, *Msg, error) {
	oob := oobPool.Get().([]byte)
	defer oobPool.Put(oob)
	n, oobn, _, _, err := s.ReadMsgUnix(b, oob)
	if err != nil {
		return 0, nil, err
	}
	// parse oob msg
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, nil, err
	}
	msg, err := parseMsg(msgs)
	if err != nil {
		return 0, nil, err
	}
	return n, msg, nil
}

func parseMsg(msgs []syscall.SocketControlMessage) (*Msg, error) {
	var msg Msg
	for _, m := range msgs {
		if m.Header.Level == syscall.SOL_SOCKET {
			switch m.Header.Type {
			case syscall.SCM_CREDENTIALS:
				cred, err := syscall.ParseUnixCredentials(&m)
				if err != nil {
					return nil, err
				}
				msg.Cred = cred

			case syscall.SCM_RIGHTS:
				fds, err := syscall.ParseUnixRights(&m)
				if err != nil {
					return nil, err
				}
				msg.Fds = fds

			}
		}
	}
	return &msg, nil
}
