// Package daemon provides pre-forked container to reduce the container
// create / destroy costs (about 160ms). It creates daemon within unshared
// container and communicate with original process using unix socket with
// oob for fd / pid and struct are encoded in gob format.
package daemon

/*
Container / Master Communication Protocol (single thread):

- ping (alive check):
  - reply: pong
- conf (set configuration):
  - reply pong
- open (open files in given mode inside container):
  - send: []OpenCmd
  - reply: "success", file fds / "error"
- delete (unlink file / rmdir dir inside container):
  - send: path
  - reply: "finished" / "error"
- reset (clean up container for later use (clear workdir / tmp)):
  - send:
  - reply: "success"
- execve: (execute file inside container):
  - send: argv, env, rLimits, fds
  - reply:
    - success: "success", pid
    - failed: "failed"
  - send (success): "init_finished" (as cmd)
    - reply: "finished" / send: "kill" (as cmd)
    - send: "kill" (as cmd) / reply: "finished"
  - reply:

Any socket related error will cause the daemon exit (with all process inside container)
*/

import (
	"os"
	"syscall"

	"github.com/criyle/go-sandbox/pkg/rlimit"
	"github.com/criyle/go-sandbox/types"
)

// Cmd is the control message send into daemon
type Cmd struct {
	Cmd string // type of the cmd

	OpenCmd   []OpenCmd  // open argument
	DeleteCmd *DeleteCmd // delete argument
	ExecCmd   *ExecCmd   // execve argument
	ConfCmd   *ConfCmd   // to set configuration
}

// OpenCmd correspond to a single open syscall
type OpenCmd struct {
	Path string
	Flag int
	Perm os.FileMode
}

// DeleteCmd stores delete command
type DeleteCmd struct {
	Path string
}

// ExecCmd stores execve parameter
type ExecCmd struct {
	Argv    []string        // execve argv
	Env     []string        // execve env
	RLimits []rlimit.RLimit // execve posix rlimit
	FdExec  bool            // if use fexecve (fd[0] as exec)
}

// ConfCmd stores conf parameter
type ConfCmd struct {
	Conf containerConfig
}

// Reply is the reply message send back to controller
type Reply struct {
	Error     *ErrorReply // nil if no error
	ExecReply *ExecReply
}

// ErrorReply stores error returned back from container
type ErrorReply struct {
	Msg   string
	Errno *syscall.Errno
}

// ExecReply stores execve result
type ExecReply struct {
	ExitStatus int          // waitpid exit status
	Status     types.Status // return status
	UserTime   uint64       // waitpid user CPU (ms)
	UserMem    uint64       // waitpid user memory (kb)
}

func (e *ErrorReply) Error() string {
	return e.Msg
}
