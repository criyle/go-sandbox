package deamon

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"

	"github.com/criyle/go-judger/unixsocket"
)

// ContainerInit is called for container init process
// it will check if pid == 1, otherwise it is noop
// ContainerInit will do infinite loop on socket commands,
// and exits when at socket close
func ContainerInit() (err error) {
	// noop if self is not container init process
	if os.Getpid() != 1 {
		return nil
	}

	// exit process (with whole container) upon exit this function
	defer func() {
		if err != nil {
			fmt.Fprintf(os.Stderr, "container_exit: %v", err)
			os.Exit(1)
		} else {
			fmt.Fprintf(os.Stderr, "container_exit")
			os.Exit(0)
		}
	}()

	// new_master shared the socket at fd 3 (marked close_exec)
	soc, err := unixsocket.NewSocket(3)
	if err != nil {
		return fmt.Errorf("container_init: faile to new socket(%v)", err)
	}
	var (
		buffer = make([]byte, bufferSize)
		cmd    Cmd
	)
	for {
		n, msg, err := soc.RecvMsg(buffer)
		if err != nil {
			return fmt.Errorf("loop: failed RecvMsg(%v)", err)
		}
		dec := gob.NewDecoder(bytes.NewReader(buffer[:n]))
		if err := dec.Decode(&cmd); err != nil {
			return fmt.Errorf("loop: failed to decode(%v)", err)
		}
		if err := handleCmd(soc, &cmd, msg); err != nil {
			return fmt.Errorf("loop: failed to execute cmd(%v)", err)
		}
	}
}

func handleCmd(s *unixsocket.Socket, cmd *Cmd, msg *unixsocket.Msg) error {
	switch cmd.Cmd {
	case cmdPing:
		return handlePing(s)
	}
	return nil
}

func handlePing(s *unixsocket.Socket) error {
	return sendReply(s, &Reply{})
}

func sendReply(s *unixsocket.Socket, reply *Reply) error {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	if err := enc.Encode(reply); err != nil {
		return err
	}
	if err := s.SendMsg(buffer.Bytes(), nil); err != nil {
		return err
	}
	return nil
}
