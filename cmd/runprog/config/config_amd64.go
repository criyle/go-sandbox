package config

// This file includes configs for the run program settings

var (
	archReadableFiles = []string{
		"/lib/x86_64-linux-gnu/",
		"/usr/lib/x86_64-linux-gnu/",
	}

	archSyscallAllows = []string{
		"dup2",
		"time",
		"arch_prctl",
	}

	archSyscallTraces = []string{
		"open",
		"unlink",
		"readlink",
		"lstat",
		"stat",
		"access",
		"newfstatat",
	}
)
