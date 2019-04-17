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
+ check file access: `stat`, `lstat`, `access`
+ check file exec: `execve`

Packages:
+ Secutil: provides common utility function that wrappers libseccomp
+ Tracee: ptraced fork-exec with seccomp loaded
+ Tracer: ptrace tracee and provides syscall trap context

Executable:
+ run_program: under construction

TODO:

Planned example config file format(yaml) `run_program.yaml`:
``` yaml
python2:
  syscall:
    extraAllow:
      - clone
    extraCount:
      set_tid_address: 1
    extraBan:
      - socket
  file:
    extraRead:
      - /usr/bin
    extraWrite:
      - ./
    extraStat:
      - /usr/bin
    extraBan:
      - /etc/passwd
```

Planned config file format for compiler `compiler.yaml`:
``` yaml
python:
  exec: python ...
  ...:
```

Planned runtime spec(yaml) `run.yaml`:
``` yaml
inputFile: input.txt
outputFile: output.txt
...:
```

+ allow multiple traced programs
+ allow pipes
+ Percise resource limits (s -> ms, mb -> kb)
+ More architectures (arm32, x86)
+ ...

Default Allowed Syscalls:
``` go
// file access through fd
"read", "write", "readv", "writev",
"close",
"fstat",
"lseek",
"dup", "dup2", "dup3",
"ioctl", "fcntl",

// memory action
"mmap", "mprotect", "munmap", "brk",
"mremap", "msync", "mincore", "madvise",

// signal action
"rt_sigaction",
"rt_sigprocmask",
"rt_sigreturn",
"rt_sigpending",
"sigaltstack",

// get current work dir
"getcwd",

// process exit
"exit",
"exit_group",

// others
"arch_prctl",

"gettimeofday",
"getrlimit",
"getrusage",
"times",
"time",
"clock_gettime",

"restart_syscall",
```

Default Allowed File Reads:
``` go
"/etc/ld.so.nohwcap",
"/etc/ld.so.preload",
"/etc/ld.so.cache",
"/lib/x86_64-linux-gnu/",
"/usr/lib/x86_64-linux-gnu/",
"/usr/lib/locale/locale-archive",
"/proc/self/exe",
"/etc/timezone",
"/usr/share/zoneinfo/",
"/dev/random",
"/dev/urandom",
"/proc/meminfo",
"/etc/localtime",
``
