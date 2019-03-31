package tracer

var (
	// default allowed safe syscalls
	defaultAllows = []string{
		// file access through fd
		"read",
		"write",
		"readv",
		"writev",
		"close",
		"fstat",
		"lseek",
		"dup",
		"dup2",
		"dup3",
		"ioctl",
		"fcntl",

		// memory action
		"mmap",
		"mprotect",
		"munmap",
		"brk",
		"mremap",
		"msync",
		"mincore",
		"madvise",

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
	}
	// default syscalls to trace
	defaultTraces = []string{
		// should be traced
		"execve",

		// file open
		"open",
		"openat",

		// file delete
		"unlink",
		"unlinkat",

		// soft link
		"readlink",
		"readlinkat",

		// permission check
		"lstat",
		"stat",
		"access",
	}
)
