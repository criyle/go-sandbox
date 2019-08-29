# go-sandbox

Original goal is to reimplement [uoj-judger/run_program](https://github.com/vfleaking/uoj) in GO language using [libseccomp](https://github.com/pkg/seccomp/libseccomp-golang). As technology grows, it also implements new technologies including Linux namespace & cgroup.

## Install

- install go compiler: `apt install golang-go`
- install libseccomp-dev: `apt install libseccomp-dev`
- install: `go install github.com/criyle/go-sandbox/...`

## Technologies

### libseccomp + ptrace (improved UOJ sandbox)

1. Restricted computing resource by POSIX rlimit: Time & Memory (Stack) & Output
2. Restricted syscall access (by libseccomp & ptrace)
3. Restricted file access (read & write & access & exec). Evaluated by UOJ FileSet

Improvements:

1. Precise resource limits (s -> ms, mb -> kb)
2. More architectures (arm32, arm64, x86)
3. Allow multiple traced programs in different threads
4. Allow pipes as input / output files

Default file access syscall check:

- check file read / write: `open`, `openat`
- check file read: `readlink`, `readlinkat`
- check file write: `unlink`, `unlinkat`, `chmod`, `rename`
- check file access: `stat`, `lstat`, `access`, `faccessat`
- check file exec: `execveat`

### linux namespace + cgroup

1. Unshare & bind mount rootfs based on hostfs (elimilated ptrace)
2. Use Linux Control Groups to limit & acct CPU & memory (elimilate wait4.rusage)
3. Container tech with execveat memfd, sethostname, setdomainname

### pre-forked container

1. Pre-fork container deamons to run programs inside
2. Unix socket to pass fd inside / outside

## Packages (/pkg)

- seccomp: provides utility function that wrappers libseccomp
- forkexec: fork-exec provides mount, unshare, ptrace, seccomp, capset before exec
- memfd: read regular file and creates a seaed memfd for its contents
- unixsocket: send / recv oob msg from a unix socket
- cgroup: creates cgroup directories and collects resource usage / limits
- mount: provides utility function that wrappers mount syscall
- rlimit: provides utility function that defines rlimit syscall

## Packages

- tracer: ptrace tracer and provides syscall trap filter context
- deamon: creates pre-forked container to run programs inside
- runprogram: wrapper to call forkexec and trecer
- rununshared: wrapper to call forkexec and unshared namespaces
- runconfig: defines arch & language specified trace condition for seccomp and ptrace
- types: general runtime specs
  - specs: provides general res / result data structures

## Executable

- run_program: safely run program by unshare / ptrace / pre-forked containers

## Configurations

- run_program/config.go: all configs toward running specs

## Benchmarks (docker desktop amd64 / native arm64)

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
BenchmarkSimpleFork-4              	   10000	   1106064 ns/op
BenchmarkUnsharePid-4              	   10000	   1367824 ns/op
BenchmarkUnshareUser-4             	   10000	   1311523 ns/op
BenchmarkUnshareUts-4              	   10000	   1140427 ns/op
BenchmarkUnshareCgroup-4           	   10000	   1112713 ns/op
BenchmarkUnshareIpc-4              	     300	  58730786 ns/op
BenchmarkUnshareMount-4            	     300	  55540758 ns/op
BenchmarkUnshareNet-4              	     100	 396957720 ns/op
BenchmarkFastUnshareMountPivot-4   	     100	 114364585 ns/op
BenchmarkUnshareAll-4              	     100	 851014031 ns/op
BenchmarkUnshareMountPivot-4       	      20	 901204445 ns/op
PASS
ok  	github.com/criyle/go-sandbox/pkg/forkexec	262.112s
```

## TODO
