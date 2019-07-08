## go-judger

Under developing.

Goal is to reimplement [uoj-judger/run_program](https://github.com/vfleaking/uoj) in GO language using [libseccomp](https://github.com/seccomp/libseccomp-golang).

Install:

+ install go compiler: `apt install golang-go`
+ install libseccomp-dev: `apt install libseccomp-dev`
+ install: `go install github.com/criyle/go-judger/...`

Features (same as uoj-judger/run_program):

1. Restricted computing resource: Time & Memory (Stack) & Output
1. Restricted syscall access (by libseccomp & ptrace)
1. Restricted file access (read & write & access & exec)

New Features:

1. Percise resource limits (s -> ms, mb -> kb)
1. More architectures (arm32, arm64, x86)
1. Allow multiple traced programs in different threads
1. Allow pipes as input / output files

Default file access action:

+ check file read / write: `open`, `openat`
+ check file read: `readlink`, `readlinkat`
+ check file write: `unlink`, `unlinkat`, `chmod`, `rename`
+ check file access: `stat`, `lstat`, `access`, `faccessat`
+ check file exec: `execve`

Packages:

+ secutil: provides common utility function that wrappers libseccomp
+ tracee: ptraced fork-exec with seccomp loaded
+ tracer: ptrace tracee and provides syscall trap context
+ runprogram: wrapper to call trecee and trecer
+ runconfig: defines arch & language specified trace condition

Executable:

+ run_program: under construction

Configuations:

+ run_program/config.go: all configs toward running specs

TODO:
1. Use Linux Namespace to isolate file access (elimilate ptrace)
1. Use Linux Control Groups to limit & acct CPU & memory (elimilate wait4 rusage)
