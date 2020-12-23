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
		"python2.7": {
			Syscall: SyscallConfig{
				ExtraAllow: []string{
					"futex", "getdents", "getdents64", "prlimit64", "getpid", "sysinfo",
				},
				ExtraCount: map[string]int{
					"set_tid_address": 1,
					"set_robust_list": 1,
				},
			},
			FileAccess: FileAccessConfig{
				ExtraRead: []string{
					"/usr/bin/python2.7",
					"/usr/lib/python2.7/",
					"/usr/bin/lib/python2.7/",
					"/usr/local/lib/python2.7/",
					"/usr/lib/pymodules/python2.7/",
					"/usr/bin/Modules/",
					"/usr/bin/pybuilddir.txt",
					"/usr/lib/locale/",
					"./answer.code",
				},
				ExtraStat: []string{
					"/usr", "/usr/bin",
				},
			},
			RunCommand: []string{"/usr/bin/python2.7", "-E", "-s", "-B"},
		},
		"python3": {
			Syscall: SyscallConfig{
				ExtraAllow: []string{
					"futex", "getdents", "getdents64", "prlimit64", "getpid", "sysinfo", "getrandom",
				},
				ExtraCount: map[string]int{
					"set_tid_address": 1,
					"set_robust_list": 1,
				},
			},
			FileAccess: FileAccessConfig{
				ExtraRead: []string{
					"/usr/bin/python3",
					"/usr/lib/python3/",
					"/usr/bin/python3.6",
					"/usr/lib/python3.6/",
					"/usr/bin/lib/python3.6/",
					"/usr/local/lib/python3.6/",
					"/usr/bin/pyvenv.cfg",
					"/usr/pyvenv.cfg",
					"/usr/bin/Modules",
					"/usr/bin/pybuilddir.txt",
					"/usr/lib/dist-python",
					"/usr/lib/locale/",
					"./answer.code",
				},
				ExtraStat: []string{
					"/usr", "/usr/bin", "/usr/lib", "/usr/lib/python36.zip",
				},
			},
			RunCommand: []string{"/usr/bin/python3", "-I", "-B"},
		},
		"compiler": {
			Syscall: SyscallConfig{
				ExtraAllow: []string{
					"gettid", "set_tid_address", "set_robust_list", "futex",
					"getpid", "vfork", "fork", "clone", "execve", "wait4",
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
