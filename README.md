## go-judger

Under developing.

Goal is to reimplement [uoj-judger/run_program](https://github.com/vfleaking/uoj) in GO language using [libseccomp](https://github.com/seccomp/libseccomp-golang).

Install:
+ install go compiler: `apt install golang-go`
+ install libseccomp-dev: `apt install libseccomp-dev`
+ install: `go get -d github.com/criyle/go-judger`

Features (same as uoj-judger/run_program):
1. Restricted computing resource: Time / Memory (Stack) / Output
2. Restricted syscall access (by libseccomp / ptrace)
3. Restricted file access (read / write / access / exec)

Default file access action:
+ check file read / write: `open`, `openat`
+ check file read: `readlink`, `readlinkat`
+ check file write: `unlink`, `unlinkat`, `chmod`, `rename`
+ check file access: `stat`, `lstat`, `access`
+ check file exec: `execve`

Packages:
+ Tracee: fork-exec with seccomp loaded
+ Tracer: ptrace tracee and provides syscall trap

Executable:
+ run_program: under construction

TODO:

Planned example config file format(yaml):
``` yaml
python2:
  + extra_syscall_allow:
    - clone
  + extra_syscall_count:
    - set_tid_address: 1
  + extra_syscall_ban:
    - socket
  + extra_file_read:
    - /usr/bin
  + extra_file_write:
    - ./
  + extra_file_stat:
    - /usr/bin
```

+ allow multiple traced programs
+ FD table instead of file names and allow pipes
+ Percise resource limits (s -> ms, mb -> kb)
+ More architectures (arm32, x86)
+ ...
