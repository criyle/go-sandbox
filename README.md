## go-judger

Under developing.

Goal is to reimplement [uoj-judger/run_program](https://github.com/vfleaking/uoj) in GO language using [libseccomp](https://github.com/seccomp/libseccomp-golang).

Features (same as uoj-judger):

1. Restricted computing resource: Time / Memory (Stack) / Output
2. Restricted syscall access (by libseccomp / ptrace)
3. Restricted file access (read / write / access / exec)

Planed features:
1. Enhanced memory allocation check (e.g. trace brk rtval)
2. More architectures
3. ...

Default file access action:
+ check file read / write: `open`, `openat`
+ check file read: `readlink`, `readlinkat`
+ check file write: `unlink`, `unlinkat`, `chmod`, `rename`
+ check file access: `stat`, `lstat`, `access`
+ check file exec: `execve`

Build dependency:
+ install libseccomp-dev: `apt install libseccomp-dev` on ubuntu
+ ...

Packages:
+ Tracee: fork-exec with seccomp loaded
+ Tracer: ptrace tracee and provides syscall trap

Executable:
+ Runner: demo
