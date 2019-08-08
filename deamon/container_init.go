package deamon

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"
	"syscall"

	"github.com/criyle/go-judger/forkexec"
	"github.com/criyle/go-judger/types/specs"
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
	for {
		cmd, msg, err := recvCmd(soc)
		if err != nil {
			return fmt.Errorf("loop: %v", err)
		}
		if err := handleCmd(soc, cmd, msg); err != nil {
			return fmt.Errorf("loop: failed to execute cmd(%v)", err)
		}
	}
}

func handleCmd(s *unixsocket.Socket, cmd *Cmd, msg *unixsocket.Msg) error {
	switch cmd.Cmd {
	case cmdPing:
		return handlePing(s)
	case cmdExecve:
		return handleExecve(s, cmd, msg)
	}
	return nil
}

func handlePing(s *unixsocket.Socket) error {
	return sendReply(s, &Reply{}, nil)
}

func handleExecve(s *unixsocket.Socket, cmd *Cmd, msg *unixsocket.Msg) error {
	var files []uintptr
	if msg != nil {
		files = intSliceToUintptr(msg.Fds)
	}

	syncFunc := func(pid int) error {
		msg2 := unixsocket.Msg{
			Cred: &syscall.Ucred{
				Pid: int32(pid),
				Uid: uint32(syscall.Getuid()),
				Gid: uint32(syscall.Getgid()),
			},
		}
		if err2 := sendReply(s, &Reply{}, &msg2); err2 != nil {
			return fmt.Errorf("syncFunc: sendReply(%v)", err2)
		}
		cmd2, _, err2 := recvCmd(s)
		if err2 != nil {
			return fmt.Errorf("syncFunc: recvCmd(%v)", err2)
		}
		switch cmd2.Cmd {
		case cmdKill:
			return fmt.Errorf("syncFunc: recved kill")
		}
		return nil
	}
	r := forkexec.Runner{
		Args:       cmd.Argv,
		Env:        cmd.Envv,
		RLimits:    cmd.RLmits,
		Files:      files,
		WorkDir:    "/w",
		NoNewPrivs: true,
		DropCaps:   true,
		SyncFunc:   syncFunc,
	}
	pid, err := r.Start()
	if err != nil {
		reply := Reply{Error: fmt.Sprintf("execve: %v", err)}
		sendReply(s, &reply, nil)
		return nil
	}

	done := make(chan int)
	// recv kill
	go func() {
		// msg must be kill
		recvCmd(s)
		// kill all
		syscall.Kill(-1, syscall.SIGKILL)
		// collect zombies
		for {
			_, err = syscall.Wait4(-1, nil, 0, nil)
			if err != nil {
				break
			}
		}
		// signal done
		close(done)
	}()

	// wait pid
	var wstatus syscall.WaitStatus
loop:
	for {
		_, err = syscall.Wait4(pid, &wstatus, 0, nil)
		if err != nil {
			reply := Reply{Error: fmt.Sprintf("execve: wait4 %v", err)}
			sendReply(s, &reply, nil)
			break loop
		}
		switch {
		case wstatus.Exited():
			reply := Reply{ExitStatus: wstatus.ExitStatus()}
			sendReply(s, &reply, nil)
			break loop

		case wstatus.Signaled():
			var status specs.TraceCode
			switch wstatus.Signal() {
			// kill signal treats as TLE
			case syscall.SIGKILL:
				status = specs.TraceCodeTLE
			case syscall.SIGXCPU:
				status = specs.TraceCodeTLE
			case syscall.SIGXFSZ:
				status = specs.TraceCodeOLE
			case syscall.SIGSYS:
				status = specs.TraceCodeBan
			default:
				status = specs.TraceCodeRE
			}
			reply := Reply{TraceStatus: status}
			sendReply(s, &reply, nil)
			break loop
		}
	}
	// wait for kill msg and reply done for finish
	<-done
	return sendReply(s, &Reply{}, nil)
}

func recvCmd(s *unixsocket.Socket) (*Cmd, *unixsocket.Msg, error) {
	var cmd Cmd
	buffer := GetBuffer()
	defer PutBuffer(buffer)
	n, msg, err := s.RecvMsg(buffer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed RecvMsg(%v)", err)
	}
	dec := gob.NewDecoder(bytes.NewReader(buffer[:n]))
	if err := dec.Decode(&cmd); err != nil {
		return nil, nil, fmt.Errorf("failed to decode(%v)", err)
	}
	return &cmd, msg, nil
}

func sendReply(s *unixsocket.Socket, reply *Reply, msg *unixsocket.Msg) error {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	if err := enc.Encode(reply); err != nil {
		return err
	}
	if err := s.SendMsg(buffer.Bytes(), msg); err != nil {
		return err
	}
	return nil
}
