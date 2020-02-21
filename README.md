# go-sandbox

[![GoDoc](https://godoc.org/github.com/criyle/go-sandbox?status.svg)](https://godoc.org/github.com/criyle/go-sandbox)

Original goal was to replica [uoj-judger/run_program](https://github.com/vfleaking/uoj) in GO language using [libseccomp](https://github.com/pkg/seccomp/libseccomp-golang). As technology grows, it also implements new technologies including Linux namespace and cgroup.

The idea of rootfs and interval CPU usage checking comes from [syzoj/judge-v3](https://github.com/syzoj/judge-v3) and the pooled pre-forked container comes from [vijos/jd4](https://github.com/vijos/jd4).

Notice: Only works on Linux since ptrace, unshare, cgroup are available only on Linux

## Build & Install

- install latest go compiler from [golang/download](https://golang.org/dl/)
- install libseccomp library: (for Ubuntu) `apt install libseccomp-dev`
- build & install: `go install github.com/criyle/go-sandbox/...`

## Technologies

### libseccomp + ptrace (improved UOJ sandbox)

1. Restricted computing resource by POSIX rlimit: Time & Memory (Stack) & Output
2. Restricted syscall access (by libseccomp & ptrace)
3. Restricted file access (read & write & access & exec). Evaluated by UOJ FileSet

Improvements:

1. Precise resource limits (s -> ms, mb -> kb)
2. More architectures (arm32, arm64)
3. Allow multiple traced programs in different threads
4. Allow pipes as input / output files

Default file access syscall check:

- check file read / write: `open`, `openat`
- check file read: `readlink`, `readlinkat`
- check file write: `unlink`, `unlinkat`, `chmod`, `rename`
- check file access: `stat`, `lstat`, `access`, `faccessat`
- check file exec: `execve`, `execveat`

### linux namespace + cgroup

1. Unshare & bind mount rootfs based on hostfs (elimilated ptrace)
2. Use Linux Control Groups to limit & acct CPU & memory (elimilate wait4.rusage)
3. Container tech with execveat memfd, sethostname, setdomainname

## Design (in progress)

### Result Status

- Normal (no error)
- Program Error
  - Resource Limit Exceeded
    - Time
    - Memory
    - Output
  - Unauthorized Access
    - Disallowed Syscall
  - Runtime Error
    - Signalled
      - `SIGXCPU` / `SIGKILL` are treated as TimeLimitExceeded by rlimit or caller kill
      - `SIGXFSZ` is treated as OutputLimitExceeded by rlimit
      - `SIGSYS` is treaded as Disallowed Syscall by seccomp
      - Potential Runtime error are: `SIGSEGV` (segment fault)
    - Nonzero Exit Status
- Program Runner Error

### Result Structure

``` go
type Result struct {
    Status            // result status
    ExitStatus int    // exit status (signal number if signalled)
    Error      string // potential detailed error message (for program runner error)

    Time   time.Duration // used user CPU time  (underlying type int64 in ns)
    Memory Size          // used user memory    (underlying type uint64 in bytes)
    // metrics for the program runner
    SetUpTime   time.Duration
    RunningTime time.Duration
}
```

### Runner Interface

Configured runner to run the program. `Context` is used to cancel (control time limit exceeded event; should not be nil).

``` go
type Runner interface {
  Run(context.Context) <-chan types.Result
}
```

### Pre-forked Container Protocol

1. Pre-fork container to run programs inside
2. Unix socket to pass fd inside / outside

Container / Host Communication Protocol (single thread):

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

Any socket related error will cause the container exit (with all process inside container)

### Pre-forked Container Environment

Container restricted environment is accessed though RPC interface defined by above protocol

Provides:

- File access
  - Open: create / access files
  - Delete: remove file
- Management
  - Ping: alive check
  - Reset: remove temporary files
  - Destroy: destroy the container environment
- Run program
  - Execve: execute program with given parameters

``` go
type Environment interface {
    Ping() error
    Open([]OpenCmd) ([]*os.File, error)
    Delete(p string) error
    Reset() error
    Execve(context.Context, ExecveParam) <-chan types.Result
    Destroy() error
}
```

## Packages (/pkg)

- seccomp: provides seccomp type definition
  - libseccomp: provides utility function that wrappers libseccomp
- forkexec: fork-exec provides mount, unshare, ptrace, seccomp, capset before exec
- memfd: read regular file and creates a seaed memfd for its contents
- unixsocket: send / recv oob msg from a unix socket
- cgroup: creates cgroup directories and collects resource usage / limits
- mount: provides utility function that wrappers mount syscall
- rlimit: provides utility function that defines rlimit syscall
- pipe: provides wrapper to collect all written content through pipe

## Packages

- config: defines arch & language specified trace condition for ptrace runner from UOJ
- container: creates pre-forked container to run programs inside
- runner: interface to run program
  - ptrace: wrapper to call forkexec and ptracer
    - filehandler: an example implementation of UOJ file set
  - unshare: wrapper to call forkexec and unshared namespaces
- ptracer: ptrace tracer and provides syscall trap filter context
- types: provides general res / result data structures

## Executable

- runprog: safely run program by unshare / ptrace / pre-forked containers

## Configurations

- config/config.go: all configs toward running specs (similar to UOJ)

## Benchmarks (MacOS docker amd64 / native arm64)

- 1ms / 2ms: fork, unshare pid / user / cgroup
- 4ms / 8ms: run inside pre-forked container
- 50ms / 25ms: unshare ipc / mount
- 100ms / 44ms: unshare pid & user & cgroup & mount & pivot root
- 400ms / 63ms: unshare net
- 800ms / 170ms: unshare all
- 880ms / 170ms: unshare all & pivot root

It seems unshare net or ipc takes time, maybe limits action by seccomp instead.
Pre-forked container also saves time for container creation / cleanup.

```bash
$ go test -bench . -benchtime 10s
goos: linux
goarch: amd64
pkg: github.com/criyle/go-sandbox/pkg/forkexec
BenchmarkSimpleFork-4              	   12789	    870486 ns/op
BenchmarkUnsharePid-4              	   13172	    917304 ns/op
BenchmarkUnshareUser-4             	   13148	    927952 ns/op
BenchmarkUnshareUts-4              	   13170	    884606 ns/op
BenchmarkUnshareCgroup-4           	   13650	    895186 ns/op
BenchmarkUnshareIpc-4              	     196	  66418708 ns/op
BenchmarkUnshareMount-4            	     243	  46957682 ns/op
BenchmarkUnshareNet-4              	     100	 411869776 ns/op
BenchmarkFastUnshareMountPivot-4   	     120	 107310917 ns/op
BenchmarkUnshareAll-4              	     100	 837352275 ns/op
BenchmarkUnshareMountPivot-4       	      12	 913099234 ns/op
PASS
ok  	github.com/criyle/go-sandbox/pkg/forkexec	300.744s
```
