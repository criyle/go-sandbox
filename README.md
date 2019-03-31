## go-judger

Under developing.

Goal is to reimplement [uoj-judger/run_program](https://github.com/vfleaking/uoj) in GO language using [libseccomp](https://github.com/seccomp/libseccomp-golang).

Features (same as uoj-judger):

1. Restricted computing resource: Time / Memory (Stack) / Output
2. Restricted syscall access (by libseccomp / ptrace)
3. Restricted file access (read / write / access / exec)

Planed features:
1. Enhanced memory allocation check (trace brk)
2. ...

Default file access action:
+ check file read / write: `open`, `openat`
+ check file read: `readlink`, `readlinkat`
+ check file write: `unlink`, `unlinkat`, `chmod`, `rename`
+ check file access: `stat`, `lstat`,
+ check file exec: `execve`
