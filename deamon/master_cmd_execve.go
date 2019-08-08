package deamon

import (
	"fmt"

	"github.com/criyle/go-judger/types/rlimit"
	"github.com/criyle/go-judger/types/specs"
	"github.com/criyle/go-judger/unixsocket"
)

// ExecveParam is parameters to run process inside container
type ExecveParam struct {
	Args []string
	Envv []string
	Fds  []uintptr
	// fexecve fd
	ExecFile uintptr
	// POSIX Resource limit set by set rlimit
	RLimits []rlimit.RLimit
	// SyncFunc called with pid before execve
	SyncFunc func(pid int) error
}

// ExecveStatus is the return value for execve
// Wait channel will produce the waitpid exit status
// Kill channel will kill the process if value received
type ExecveStatus struct {
	Wait <-chan specs.TraceResult
	Kill chan<- int
}

// Execve runs process inside container
func (m *Master) Execve(param *ExecveParam) (*ExecveStatus, error) {
	var files []int
	if param.ExecFile > 0 {
		files = append(files, int(param.ExecFile))
	}
	files = append(files, uintptrSliceToInt(param.Fds)...)
	msg := &unixsocket.Msg{
		Fds: files,
	}
	cmd := Cmd{
		Cmd:    cmdExecve,
		Argv:   param.Args,
		Envv:   param.Envv,
		RLmits: param.RLimits,
		FdExec: param.ExecFile > 0,
	}
	if err := m.sendCmd(&cmd, msg); err != nil {
		return nil, fmt.Errorf("execve: sendCmd %v", err)
	}
	reply, msg, err := m.recvReply()
	if err != nil {
		return nil, fmt.Errorf("execve: RecvReply %v", err)
	}
	if reply.Error != "" || msg == nil || msg.Cred == nil {
		m.sendCmd(&Cmd{Cmd: cmdKill}, nil)
		return nil, fmt.Errorf("execve: no pid recved or error(%v)", reply.Error)
	}
	if err := param.SyncFunc(int(msg.Cred.Pid)); err != nil {
		m.sendCmd(&Cmd{Cmd: cmdKill}, nil)
		return nil, fmt.Errorf("execve: syncfunc failed(%v)", err)
	}
	if err := m.sendCmd(&Cmd{Cmd: cmdOk}, nil); err != nil {
		return nil, fmt.Errorf("execve: ok failed(%v)", err)
	}
	wait := make(chan specs.TraceResult)
	kill := make(chan int)
	// Wait
	go func() {
		reply2, _, _ := m.recvReply()
		wait <- specs.TraceResult{
			ExitCode:    reply2.ExitStatus,
			TraceStatus: reply2.TraceStatus,
		}
		// done signal (should recv after kill)
		m.recvReply()
		close(wait)
	}()
	// Kill
	go func() {
		<-kill
		m.sendCmd(&Cmd{Cmd: cmdKill}, nil)
	}()
	return &ExecveStatus{
		Wait: wait,
		Kill: kill,
	}, nil
}
