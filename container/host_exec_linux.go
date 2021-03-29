package container

import (
	"context"
	"fmt"
	"time"

	"github.com/criyle/go-sandbox/pkg/rlimit"
	"github.com/criyle/go-sandbox/pkg/seccomp"
	"github.com/criyle/go-sandbox/pkg/unixsocket"
	"github.com/criyle/go-sandbox/runner"
)

// ExecveParam is parameters to run process inside container
type ExecveParam struct {
	// Args holds command line arguments
	Args []string

	// Env specifies the environment of the process
	Env []string

	// Files specifies file descriptors for the child process
	Files []uintptr

	// ExecFile specifies file descriptor for executable file using fexecve
	ExecFile uintptr

	// RLimits specifies POSIX Resource limit through setrlimit
	RLimits []rlimit.RLimit

	// Seccomp specifies seccomp filter
	Seccomp seccomp.Filter

	// CTTY specifies whether to set controlling TTY
	CTTY bool

	// SyncFunc calls with pid just before execve (for attach the process to cgroups)
	SyncFunc func(pid int) error
}

// Execve runs process inside container. It accepts context cancelation as time limit exceeded.
func (c *container) Execve(ctx context.Context, param ExecveParam) <-chan runner.Result {
	c.mu.Lock()

	sTime := time.Now()

	// make sure goroutine not leaked (blocked) even if result is not consumed
	result := make(chan runner.Result, 1)

	errResult := func(f string, v ...interface{}) <-chan runner.Result {
		result <- runner.Result{
			Status: runner.StatusRunnerError,
			Error:  fmt.Sprintf(f, v...),
		}
		return result
	}

	// if execve with fd, put fd at the first parameter
	var files []int
	if param.ExecFile > 0 {
		files = append(files, int(param.ExecFile))
	}
	files = append(files, uintptrSliceToInt(param.Files)...)
	msg := unixsocket.Msg{
		Fds: files,
	}
	execCmd := &execCmd{
		Argv:    param.Args,
		Env:     param.Env,
		RLimits: param.RLimits,
		Seccomp: param.Seccomp,
		FdExec:  param.ExecFile > 0,
		CTTY:    param.CTTY,
	}
	cm := cmd{
		Cmd:     cmdExecve,
		ExecCmd: execCmd,
	}
	if err := c.sendCmd(cm, msg); err != nil {
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
	if reply.Error != nil || msg.Cred == nil {
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
	if err := c.sendCmd(cmd{Cmd: cmdOk}, unixsocket.Msg{}); err != nil {
		c.mu.Unlock()
		return errResult("execve: ack failed %v", err)
	}

	c.execveWait(ctx, sTime, result)

	return result
}

func (c *container) execveWait(ctx context.Context, sTime time.Time, result chan runner.Result) {
	mTime := time.Now()

	// wait for result / cancel
	go func() {
		defer c.mu.Unlock()
		select {
		case <-c.done: // socket error
			result <- convertReplyResult(reply{}, sTime, mTime, c.err)

		case <-ctx.Done(): // cancel
			c.sendCmd(cmd{Cmd: cmdKill}, unixsocket.Msg{}) // kill
			reply, _, _ := c.recvReply()
			_, _, err := c.recvReply()
			result <- convertReplyResult(reply, sTime, mTime, err)

		case ret := <-c.recvCh: // result
			c.sendCmd(cmd{Cmd: cmdKill}, unixsocket.Msg{}) // kill
			_, _, err := c.recvReply()
			result <- convertReplyResult(ret.Reply, sTime, mTime, err)
		}
	}()
}

func convertReplyResult(reply reply, sTime, mTime time.Time, err error) runner.Result {
	// handle potential error
	if err != nil {
		return runner.Result{
			Status: runner.StatusRunnerError,
			Error:  err.Error(),
		}
	}
	if reply.Error != nil {
		return runner.Result{
			Status: runner.StatusRunnerError,
			Error:  reply.Error.Error(),
		}
	}
	if reply.ExecReply == nil {
		return runner.Result{
			Status: runner.StatusRunnerError,
			Error:  "execve: no reply received",
		}
	}
	// emit result after all communication finish
	return runner.Result{
		Status:      reply.ExecReply.Status,
		ExitStatus:  reply.ExecReply.ExitStatus,
		Time:        reply.ExecReply.Time,
		Memory:      reply.ExecReply.Memory,
		SetUpTime:   mTime.Sub(sTime),
		RunningTime: time.Since(mTime),
	}
}

// execveSyncKill will send kill and recv reply
func (c *container) execveSyncKill() {
	c.sendCmd(cmd{Cmd: cmdKill}, unixsocket.Msg{})
	c.recvReply()
}
