// Package deamon provides pre-forked container to reduce the container
// create / destroy costs (about 160ms). It creates deamon within unshared
// container and communicate with original process using unix socket with
// oob for fd / pid and structs are encoded in gob format.
package deamon

/*
Protocol between client and deamon (not thread safe):
- ping (alive check):
	reply: pong
- copyin (copy file into container):
  send: path, perm, <input fd>
  reply: "finished" (after copy finished) / "error"
- open (open file inside container):
  send: path, flags, perm
  reply: "success", <file fd> / "error"
- delete (unlik file / rmdir dir inside container):
  send: path
  reply: "finished" / "error"
- reset (clean up container for later use (clear workdir / tmp)):
  send:
  reply: "success"
- execve: (execute file inside container):
  send: argv, envv, rlimits, <fds>
  reply:
    - success: "success", <pid>
    - failed: "failed"
  send (success): "init_finished" (as cmd)
    - reply: "finished" / send: "kill" (as cmd)
    - send: "kill" (as cmd) / reply: "finished"

Any socket related error will cause the deamon exit (with all process inside container)
*/

import (
	"github.com/criyle/go-judger/types/rlimit"
)

// Cmd is the control message send into deamon
type Cmd struct {
	Cmd    string          // type of the cmd
	Path   string          // path
	Perm   int             // write perm / open perm
	Flags  int             // open flags
	Argv   []string        // execve argv
	Envv   []string        // execve envv
	RLmits []rlimit.RLimit // execve posix rlimit
}

// Reply is the reply message send back to controller
type Reply struct {
	Error  string // empty if no error
	Status int    // waitpid exit status
}
