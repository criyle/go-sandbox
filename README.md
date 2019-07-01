## go-judger

Under developing.

Goal is to reimplement [uoj-judger/run_program](https://github.com/vfleaking/uoj) in GO language using [libseccomp](https://github.com/seccomp/libseccomp-golang).

Install:
+ install go compiler: `apt install golang-go`
+ install libseccomp-dev: `apt install libseccomp-dev`
+ install: `go install github.com/criyle/go-judger/...`

Features (same as uoj-judger/run_program):
1. Restricted computing resource: Time & Memory (Stack) & Output
2. Restricted syscall access (by libseccomp & ptrace)
3. Restricted file access (read & write & access & exec)

Default file access action:
+ check file read / write: `open`, `openat`
+ check file read: `readlink`, `readlinkat`
+ check file write: `unlink`, `unlinkat`, `chmod`, `rename`
+ check file access: `stat`, `lstat`, `access`, `faccessat`
+ check file exec: `execve`

Packages:
+ Secutil: provides common utility function that wrappers libseccomp
+ Tracee: ptraced fork-exec with seccomp loaded
+ Tracer: ptrace tracee and provides syscall trap context

Executable:
+ run_program: under construction

Configuations:
+ run_program/config.go: all configs toward running specs

Features:
+ Percise resource limits (s -> ms, mb -> kb)
+ More architectures (arm32, arm64, x86)

TODO:

+ allow multiple traced programs
+ allow pipes
+ ...
