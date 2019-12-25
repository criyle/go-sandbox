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
	execCmd := &ExecCmd{
		Argv:    param.Args,
		Env:     param.Env,
		RLimits: param.RLimits,
		FdExec:  param.ExecFile > 0,
	}
	cmd := Cmd{
		Cmd:     cmdExecve,
		ExecCmd: execCmd,
	}
	if err := m.sendCmd(&cmd, msg); err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("execve: sendCmd %v", err)
	}
	// sync function
	reply, msg, err := m.recvReply()
	if err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("execve: recvReply %v", err)
	}
	// if sync function did not involved
	if reply.Error != nil || msg == nil || msg.Cred == nil {
		// tell kill function to exit and sync
		m.execveSyncKill()
		m.mu.Unlock()
		return nil, fmt.Errorf("execve: no pid received or error %v", reply.Error)
	}
	if param.SyncFunc != nil {
		if err := param.SyncFunc(int(msg.Cred.Pid)); err != nil {
			// tell sync function to exit and recv error
			m.execveSyncKill()
			// tell kill function to exit and sync
			m.execveSyncKill()
			m.mu.Unlock()
			return nil, fmt.Errorf("execve: syncfunc failed %v", err)
		}
	}
	// send to syncFunc ack ok
	if err := m.sendCmd(&Cmd{Cmd: cmdOk}, nil); err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("execve: ack failed %v", err)
	}

	mTime := time.Now()

	// make sure goroutine not leaked (blocked) even if result is not consumed
	result := make(chan types.Result, 1)
	waitDone := make(chan struct{})

	// Wait
	go func() {
		reply2, _, err := m.recvReply()
		close(waitDone)
		// done signal (should recv after kill)
		m.recvReply()
		// unlock after last read / write
		m.mu.Unlock()

		// handle potential error
		if err != nil {
			result <- types.Result{
				Status: types.StatusFatal,
				Error:  err.Error(),
			}
			return
		}
		if reply2.ExecReply == nil {
			result <- types.Result{
				Status: types.StatusFatal,
				Error:  "execve: no reply received",
			}
			return
		}
		// emit result after all communication finish
		status := reply2.ExecReply.Status
		errMsg := ""
		if reply2.Error != nil {
			status = types.StatusFatal
			errMsg = reply2.Error.Error()
		}

		result <- types.Result{
			Status:      status,
			ExitStatus:  reply2.ExecReply.ExitStatus,
			UserTime:    reply2.ExecReply.UserTime,
			UserMem:     reply2.ExecReply.UserMem,
			Error:       errMsg,
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

// execveSyncKill will send kill and recv reply
func (m *Master) execveSyncKill() {
	m.sendCmd(&Cmd{Cmd: cmdKill}, nil)
	m.recvReply()
}
