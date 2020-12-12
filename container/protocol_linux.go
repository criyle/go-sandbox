package container

import (
	"os"
	"syscall"
	"time"

	"github.com/criyle/go-sandbox/pkg/mount"
	"github.com/criyle/go-sandbox/pkg/rlimit"
	"github.com/criyle/go-sandbox/pkg/seccomp"
	"github.com/criyle/go-sandbox/runner"
)

// cmd is the control message send into container
type cmd struct {
	Cmd string // type of the cmd

	OpenCmd   []OpenCmd  // open argument
	DeleteCmd *deleteCmd // delete argument
	ExecCmd   *execCmd   // execve argument
	ConfCmd   *confCmd   // to set configuration
}

// OpenCmd correspond to a single open syscall
type OpenCmd struct {
	Path string
	Flag int
	Perm os.FileMode
}

// deleteCmd stores delete command
type deleteCmd struct {
	Path string
}

// execCmd stores execve parameter
type execCmd struct {
	Argv    []string        // execve argv
	Env     []string        // execve env
	RLimits []rlimit.RLimit // execve posix rlimit
	Seccomp seccomp.Filter  // seccomp filter
	FdExec  bool            // if use fexecve (fd[0] as exec)
	CTTY    bool            // if set CTTY
}

// confCmd stores conf parameter
type confCmd struct {
	Conf containerConfig
}

// ContainerConfig set the container config
type containerConfig struct {
	WorkDir string

	HostName   string
	DomainName string

	ContainerRoot string
	Mounts        []mount.Mount

	Cred         bool
	ContainerUID int
	ContainerGID int
}

// reply is the reply message send back to controller
type reply struct {
	Error     *errorReply // nil if no error
	ExecReply *execReply
}

// errorReply stores error returned back from container
type errorReply struct {
	Msg   string
	Errno *syscall.Errno
}

// execReply stores execve result
type execReply struct {
	ExitStatus int           // waitpid exit status
	Status     runner.Status // return status
	Time       time.Duration // waitpid user CPU (ns)
	Memory     runner.Size   // waitpid user memory (byte)
}

func (e *errorReply) Error() string {
	return e.Msg
}
