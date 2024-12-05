package config

// This file includes configs for the run program settings

var (
	// default read permission files
	defaultReadableFiles = []string{
		"/etc/ld.so.nohwcap",
		"/etc/ld.so.preload",
		"/etc/ld.so.cache",
		"/usr/lib/locale/locale-archive",
		"/proc/self/exe",
		"/etc/timezone",
		"/usr/share/zoneinfo/",
		"/dev/random",
		"/dev/urandom",
		"/proc/meminfo",
		"/etc/localtime",
        "/usr/lib/libstdc++.so.6",
        "/usr/lib/libc.so.6",
        "/usr/lib/libm.so.6",
        "/usr/lib/libgcc_s.so.1",
	}

	// default write permission files
	defaultWritableFiles = []string{"/dev/null"}

	// default allowed safe syscalls
	defaultSyscallAllows = []string{
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
		"fadvise64",
		"pread64",
		"pwrite64",

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


        "futex",
        "gettid",
        "getpid",
        "prlimit64",
        "getrandom",
        "set_tid_address",
        "set_robust_list",
        "rseq",
        "newfstatat",
	}

	// default syscalls to trace
	defaultSyscallTraces = []string{
		// execute file
		"execve",
		"execveat",

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
		"faccessat",
	}

	// process related syscall if allowProc enabled
	defaultProcSyscalls = []string{"clone", "fork", "vfork", "nanosleep", "execve"}

	// config for different type of program
	// workpath and arg0 have additional read / stat permission
	runptraceConfig = map[string]ProgramConfig{
		"compiler": {
			Syscall: SyscallConfig{
				ExtraAllow: []string{
					"set_tid_address", "set_robust_list", "futex",
					"vfork", "fork", "clone", "execve", "wait4",
					"clock_gettime", "clock_getres",
					"setrlimit", "pipe",
					"getdents64", "getdents",
					"umask", "rename", "chmod", "mkdir",
					"chdir", "fchdir",
					"ftruncate",
					"sched_getaffinity", "sched_yield",
					"uname", "sysinfo",
					"prlimit64", "getrandom",
					"fchmodat",
				},
				ExtraBan: []string{"socket", "connect", "geteuid", "getuid"},
			},
			FileAccess: FileAccessConfig{
				ExtraWrite: []string{
					"/tmp/", "./",
				},
				ExtraRead: []string{
					"./",
					"../runtime/",
					"/etc/oracle/java/usagetracker.properties",
					"/usr/",
					"/lib/",
					"/lib64/",
					"/bin/",
					"/sbin/",
					"/sys/devices/system/cpu/",
					"/proc/",
					"/etc/timezone",
					"/etc/fpc-2.6.2.cfg.d/",
					"/etc/fpc.cfg",
					"/*",
					"/", // system_root
				},
				ExtraBan: []string{
					"/etc/nsswitch.conf",
					"/etc/passwd",
				},
			},
		},
	}
)
