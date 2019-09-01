package config

// This file includes configs for the run program settings

var (
	archReadableFiles = []string{
		"/lib/arm-linux-gnueabihf/",
		"/usr/lib/arm-linux-gnueabihf/",
	}

	archSyscallAllows = []string{
		"fstat64", // 32-bit
		"_llseek", // 32-bit
		"fcntl64", // 32-bit
		"mmap2",   // 32-bit
		// arch
		"uname",
		"set_tls",
		"arm_fadvise64_64",
	}

	archSyscallTraces = []string{
		"lstat64", // 32-bit
		"stat64",  // 32-bit
	}
)
