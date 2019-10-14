// Package daemon provides pre-forked container to reduce the container
// create / destroy costs (about 160ms). It creates daemon within unshared
// container and communicate with original process using unix socket with
// oob for fd / pid and struct are encoded in gob format.
package daemon

/*
Protocol between client and daemon (not thread safe):
- ping (alive check):
	reply: pong
- copyin (copy file into container):
  send: path, <input fd>
  reply: "finished" (after copy finished) / "error"
- open (open file in read-only mode inside container):
  send: path
  reply: "success", <file fd> / "error"
- delete (unlink file / rmdir dir inside container):
  send: path
  reply: "finished" / "error"
- reset (clean up container for later use (clear workdir / tmp)):
  send:
  reply: "success"
- execve: (execute file inside container):
  send: argv, env, rLimits, <fds>
  reply:
    - success: "success", <pid>
    - failed: "failed"
  send (success): "init_finished" (as cmd)
    - reply: "finished" / send: "kill" (as cmd)
    - send: "kill" (as cmd) / reply: "finished"
	reply:

Any socket related error will cause the daemon exit (with all process inside container)
*/

import (
	"github.com/criyle/go-sandbox/pkg/rlimit"
	"github.com/criyle/go-sandbox/types"
)

// Cmd is the control message send into daemon
type Cmd struct {
	Cmd     string          // type of the cmd
	Path    string          // path (copyin / open)
	Argv    []string        // execve argv
	Env     []string        // execve env
	RLimits []rlimit.RLimit // execve posix rlimit
	FdExec  bool            // if use fexecve (fd[0] as exec)
}

// Reply is the reply message send back to controller
type Reply struct {
	Error      string       // empty if no error
	ExitStatus int          // waitpid exit status
	Status     types.Status // return status
	UserTime   uint64       // waitpid user CPU (ms)
	UserMem    uint64       // waitpid user memory (kb)
}
