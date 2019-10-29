package daemon

import (
	"fmt"
	"time"

	"github.com/criyle/go-sandbox/pkg/rlimit"
	"github.com/criyle/go-sandbox/pkg/unixsocket"
	"github.com/criyle/go-sandbox/types"
)

// ExecveParam is parameters to run process inside container
type ExecveParam struct {
	Args []string
	Env  []string
	Fds  []uintptr

	// fexecve fd
	ExecFile uintptr

	// POSIX Resource limit set by set rlimit
	RLimits []rlimit.RLimit

	// SyncFunc called with pid before execve (e.g. add to cgroup)
	SyncFunc func(pid int) error
}

// Execve runs process inside container
// accepts done for cancelation
func (m *Master) Execve(done <-chan struct{}, param *ExecveParam) (<-chan types.Result, error) {
	m.mu.Lock()

	sTime := time.Now()

	// if execve with fd, put fd at the first parameter
	var files []int
	if param.ExecFile > 0 {
		files = append(files, int(param.ExecFile))
	}
	files = append(files, uintptrSliceToInt(param.Fds)...)
	msg := &unixsocket.Msg{
		Fds: files,
	}
	cmd := Cmd{
		Cmd:     cmdExecve,
		Argv:    param.Args,
		Env:     param.Env,
		RLimits: param.RLimits,
		FdExec:  param.ExecFile > 0,
	}
	if err := m.sendCmd(&cmd, msg); err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("execve: sendCmd %v", err)
	}
	reply, msg, err := m.recvReply()
	if err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("execve: recvReply %v", err)
	}
	if reply.Error != "" || msg == nil || msg.Cred == nil {
		m.execveSyncKill()
		m.mu.Unlock()
		return nil, fmt.Errorf("execve: no pid recved or error(%v)", reply.Error)
	}
	if param.SyncFunc != nil {
		if err := param.SyncFunc(int(msg.Cred.Pid)); err != nil {
			m.execveSyncKill()
			m.mu.Unlock()
			return nil, fmt.Errorf("execve: syncfunc failed(%v)", err)
		}
	}
	// send to syncFunc ack ok
	if err := m.sendCmd(&Cmd{Cmd: cmdOk}, nil); err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("execve: ok failed(%v)", err)
	}

	mTime := time.Now()

	// make sure goroutine not leaked (blocked) even if result is not consumed
	result := make(chan types.Result, 1)
	waitDone := make(chan struct{})

	// Wait
	go func() {
		reply2, _, _ := m.recvReply()
		close(waitDone)
		// done signal (should recv after kill)
		m.recvReply()
		// unlock after last read / write
		m.mu.Unlock()
		// emit result after all communication finish
		status := reply2.Status
		if reply2.Error != "" {
			status = types.StatusFatal
		}
		result <- types.Result{
			Status:      status,
			ExitStatus:  reply2.ExitStatus,
			UserTime:    reply2.UserTime,
			UserMem:     reply2.UserMem,
			Error:       reply2.Error,
			SetUpTime:   mTime.Sub(sTime),
			RunningTime: time.Since(mTime),
		}
	}()

	// Kill (if wait is done, a kill message need to be send to collect zombies)
	go func() {
		select {
		case <-done:
		case <-waitDone:
		}
		m.sendCmd(&Cmd{Cmd: cmdKill}, nil)
	}()

	return result, nil
}

// handleSyncKill will send kill (for sync func), kill (for wait to kill all) and
// then recv error and finish signal when terminated by syncFunc error
func (m *Master) execveSyncKill() {
	m.sendCmd(&Cmd{Cmd: cmdKill}, nil)
	m.sendCmd(&Cmd{Cmd: cmdKill}, nil)
	m.recvReply()
	m.recvReply()
}