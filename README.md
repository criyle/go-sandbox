## go-judger

Under developing.

Goal is to reimplement [uoj-judger/run_program](https://github.com/vfleaking/uoj) in GO language using [libseccomp](https://github.com/seccomp/libseccomp-golang).

Install:

-   install go compiler: `apt install golang-go`
-   install libseccomp-dev: `apt install libseccomp-dev`
-   install: `go install github.com/criyle/go-judger/...`

Features (same as uoj-judger/run_program):

1.  Restricted computing resource: Time & Memory (Stack) & Output
2.  Restricted syscall access (by libseccomp & ptrace)
3.  Restricted file access (read & write & access & exec)

New Features:

1.  Percise resource limits (s -> ms, mb -> kb)
2.  More architectures (arm32, arm64, x86)
3.  Allow multiple traced programs in different threads
4.  Allow pipes as input / output files
5.  Use Linux Namespace to isolate file access (elimilate ptrace)
6.  Use Linux Control Groups to limit & acct CPU & memory (elimilate wait4.rusage)
7.  Container tech with execveat memfd, sethostname, setdomainname
8.  Pre-fork container deamons to run programs inside

Default file access action:

-   check file read / write: `open`, `openat`
-   check file read: `readlink`, `readlinkat`
-   check file write: `unlink`, `unlinkat`, `chmod`, `rename`
-   check file access: `stat`, `lstat`, `access`, `faccessat`
-   check file exec: `execveat`

Packages:

-   seccomp: provides utility function that wrappers libseccomp
-   forkexec: fork-exec provides mount, unshare, ptrace, seccomp, capset before exec
-   memfd: read regular file and creates a seaed memfd for its contents
-   unixsocket: send / recv oob msg from a unix socket
-   cgroup: creates cgroup directories and collects resource usage / limits
-   deamon: creates pre-forked container to run programs inside
-   tracer: ptrace tracer and provides syscall trap filter context
-   runprogram: wrapper to call forkexec and trecer
-   rununshared: wrapper to call forkexec and unshared namespaces
-   runconfig: defines arch & language specified trace condition for seccomp and ptrace
-   types: general runtime specs
    -   mount: provides utility function that wrappers mount syscall
    -   rlimit: provides utility function that defines rlimit syscall
    -   specs: provides general res / result data structures

Executable:

-   run_program: safely run program by unshare / ptrace / pre-forked containers

Configuations:

-   run_program/config.go: all configs toward running specs

Benchmarks (docker desktop amd64 / native arm64):

-   1ms / 2ms: fork, unshare pid / user / cgroup
-   4ms / 8ms: run inside pre-forked container
-   50ms / 25ms: unshare ipc / mount
-   100ms / 44ms: unshare pid & user & cgroup & mount & pivot root
-   400ms / 63ms: unshare net
-   800ms / 170ms: unshare all
-   880ms / 170ms: unshare all & pivot root

It seems unshare net or ipc takes time, maybe limits action by seccomp instead.
Pre-forked container also saves time for container creation / cleanup.

TODO:
