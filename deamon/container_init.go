package deamon

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/criyle/go-sandbox/forkexec"
	"github.com/criyle/go-sandbox/types/specs"
	"github.com/criyle/go-sandbox/unixsocket"
)

// ContainerInit is called for container init process
// it will check if pid == 1, otherwise it is noop
// ContainerInit will do infinite loop on socket commands,
// and exits when at socket close
func ContainerInit() (err error) {
	// noop if self is not container init process
	// Notice: docker init is also 1, additional check for args[1] == init
	if os.Getpid() != 1 || len(os.Args) != 2 || os.Args[1] != initArg {
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

	case cmdCopyIn:
		return handleCopyIn(s, cmd, msg)

	case cmdOpen:
		return handleOpen(s, cmd)

	case cmdDelete:
		return handleDelete(s, cmd)

	case cmdReset:
		return handleReset(s)

	case cmdExecve:
		return handleExecve(s, cmd, msg)
	}
	return nil
}

func handlePing(s *unixsocket.Socket) error {
	return sendReply(s, &Reply{}, nil)
}

func handleCopyIn(s *unixsocket.Socket, cmd *Cmd, msg *unixsocket.Msg) error {
	if len(msg.Fds) == 0 {
		return sendErrorReply(s, "copyin: did not receive fd")
	}
	inf := os.NewFile(uintptr(msg.Fds[0]), cmd.Path)
	if inf == nil {
		return sendErrorReply(s, "copyin: newfile failed %v", msg.Fds[0])
	}
	defer inf.Close()

	outf, err := os.OpenFile(cmd.Path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		return sendErrorReply(s, "copyin: open write file %v", err)
	}
	defer outf.Close()

	_, err = io.Copy(outf, inf)
	if err != nil {
		return sendErrorReply(s, "copyin: io.copy %v", err)
	}
	return sendReply(s, &Reply{}, nil)
}

func handleOpen(s *unixsocket.Socket, cmd *Cmd) error {
	outf, err := os.Open(cmd.Path)
	if err != nil {
		return sendErrorReply(s, "open: %v", err)
	}
	defer outf.Close()

	msg := unixsocket.Msg{
		Fds: []int{int(outf.Fd())},
	}
	return sendReply(s, &Reply{}, &msg)
}

func handleDelete(s *unixsocket.Socket, cmd *Cmd) error {
	err := os.Remove(cmd.Path)
	if err != nil {
		return sendErrorReply(s, "delete: %v", err)
	}
	return sendReply(s, &Reply{}, nil)
}

func handleReset(s *unixsocket.Socket) error {
	err := removeContents("/tmp")
	if err != nil {
		return sendErrorReply(s, "reset: /tmp %v", err)
	}
	err = removeContents("/w")
	if err != nil {
		return sendErrorReply(s, "reset: /w %v", err)
	}
	return sendReply(s, &Reply{}, nil)
}

func handleExecve(s *unixsocket.Socket, cmd *Cmd, msg *unixsocket.Msg) error {
	var (
		files    []uintptr
		execFile uintptr
	)
	if msg != nil {
		files = intSliceToUintptr(msg.Fds)
	}
	// don't leak fds to child
	closeOnExecFds(msg.Fds)
	// release files after execve
	defer closeFds(msg.Fds)

	if cmd.FdExec && len(files) > 0 {
		execFile = files[0]
		files = files[1:]
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
		ExecFile:   execFile,
		RLimits:    cmd.RLmits,
		Files:      files,
		WorkDir:    "/w",
		NoNewPrivs: true,
		DropCaps:   true,
		SyncFunc:   syncFunc,
	}
	pid, err := r.Start()
	if err != nil {
		return sendErrorReply(s, "execve: %v", err)
	}

	// done is to signal kill goroutine exits
	done := make(chan struct{})
	// waitDone is to signal kill goroutine to collect zombies
	waitDone := make(chan struct{})

	// recv kill
	go func() {
		// signal done
		defer close(done)
		// msg must be kill
		recvCmd(s)
		// kill all
		syscall.Kill(-1, syscall.SIGKILL)
		// make sure collect zombie does not consume the exit status
		<-waitDone
		// collect zombies
		for {
			_, err = syscall.Wait4(-1, nil, syscall.WNOHANG, nil)
			if err != nil {
				break
			}
		}
	}()

	// wait pid
	var wstatus syscall.WaitStatus
loop:
	for {
		_, err = syscall.Wait4(pid, &wstatus, 0, nil)
		// sync with kill goroutine
		close(waitDone)
		if err != nil {
			sendErrorReply(s, "execve: wait4 %v", err)
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
			case syscall.SIGXCPU, syscall.SIGKILL:
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
	if err := gob.NewDecoder(bytes.NewReader(buffer[:n])).Decode(&cmd); err != nil {
		return nil, nil, fmt.Errorf("failed to decode(%v)", err)
	}
	return &cmd, msg, nil
}

func sendReply(s *unixsocket.Socket, reply *Reply, msg *unixsocket.Msg) error {
	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(reply); err != nil {
		return err
	}
	if err := s.SendMsg(buffer.Bytes(), msg); err != nil {
		return err
	}
	return nil
}

// sendErrorReply sends error reply
func sendErrorReply(s *unixsocket.Socket, ft string, v ...interface{}) error {
	reply := Reply{Error: fmt.Sprintf(ft, v...)}
	return sendReply(s, &reply, nil)
}
