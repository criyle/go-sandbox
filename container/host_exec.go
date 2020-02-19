package container

import (
	"context"
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

	// fd parameter of fexecve
	ExecFile uintptr

	// POSIX Resource limit set by set rlimit
	RLimits []rlimit.RLimit

	// SyncFunc called with pid before execve (for adding the process to cgroups)
	SyncFunc func(pid int) error
}

// Execve runs process inside container. It accepts context cancelation as time limit exceeded.
func (c *container) Execve(ctx context.Context, param ExecveParam) <-chan types.Result {
	c.mu.Lock()

	sTime := time.Now()

	// make sure goroutine not leaked (blocked) even if result is not consumed
	result := make(chan types.Result, 1)

	errResult := func(f string, v ...interface{}) <-chan types.Result {
		result <- types.Result{
			Status: types.StatusRunnerError,
			Error:  fmt.Sprintf(f, v...),
		}
		return result
	}

	// if execve with fd, put fd at the first parameter
	var files []int
	if param.ExecFile > 0 {
		files = append(files, int(param.ExecFile))
	}
	files = append(files, uintptrSliceToInt(param.Fds)...)
	msg := &unixsocket.Msg{
		Fds: files,
	}
	execCmd := &execCmd{
		Argv:    param.Args,
		Env:     param.Env,
		RLimits: param.RLimits,
		FdExec:  param.ExecFile > 0,
	}
	cm := cmd{
		Cmd:     cmdExecve,
		ExecCmd: execCmd,
	}
	if err := c.sendCmd(&cm, msg); err != nil {
		c.mu.Unlock()
		return errResult("execve: sendCmd %v", err)
	}
	// sync function
	reply, msg, err := c.recvReply()
	if err != nil {
		c.mu.Unlock()
		return errResult("execve: recvReply %v", err)
	}
	// if sync function did not involved
	if reply.Error != nil || msg == nil || msg.Cred == nil {
		// tell kill function to exit and sync
		c.execveSyncKill()
		c.mu.Unlock()
		return errResult("execve: no pid received or error %v", reply.Error)
	}
	if param.SyncFunc != nil {
		if err := param.SyncFunc(int(msg.Cred.Pid)); err != nil {
			// tell sync function to exit and recv error
			c.execveSyncKill()
			// tell kill function to exit and sync
			c.execveSyncKill()
			c.mu.Unlock()
			return errResult("execve: syncfunc failed %v", err)
		}
	}
	// send to syncFunc ack ok
	if err := c.sendCmd(&cmd{Cmd: cmdOk}, nil); err != nil {
		c.mu.Unlock()
		return errResult("execve: ack failed %v", err)
	}

	mTime := time.Now()

	waitDone := make(chan struct{})

	// Wait
	go func() {
		reply2, _, err := c.recvReply()
		close(waitDone)
		// done signal (should recv after kill)
		c.recvReply()
		// unlock after last read / write
		c.mu.Unlock()

		// handle potential error
		if err != nil {
			result <- types.Result{
				Status: types.StatusRunnerError,
				Error:  err.Error(),
			}
			return
		}
		if reply2.Error != nil {
			result <- types.Result{
				Status: types.StatusRunnerError,
				Error:  reply2.Error.Error(),
			}
			return
		}
		if reply2.ExecReply == nil {
			result <- types.Result{
				Status: types.StatusRunnerError,
				Error:  "execve: no reply received",
			}
			return
		}
		// emit result after all communication finish
		result <- types.Result{
			Status:      reply2.ExecReply.Status,
			ExitStatus:  reply2.ExecReply.ExitStatus,
			Time:        reply2.ExecReply.Time,
			Memory:      reply2.ExecReply.Memory,
			SetUpTime:   mTime.Sub(sTime),
			RunningTime: time.Since(mTime),
		}
	}()

	// Kill (if wait is done, a kill message need to be send to collect zombies)
	go func() {
		select {
		case <-ctx.Done():
		case <-waitDone:
		}
		c.sendCmd(&cmd{Cmd: cmdKill}, nil)
	}()

	return result
}

// execveSyncKill will send kill and recv reply
func (c *container) execveSyncKill() {
	c.sendCmd(&cmd{Cmd: cmdKill}, nil)
	c.recvReply()
}
