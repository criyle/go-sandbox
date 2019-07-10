package forkexec

import "syscall"

// defines missing consts from syscall package
const (
	SECCOMP_SET_MODE_STRICT   = 0
	SECCOMP_SET_MODE_FILTER   = 1
	SECCOMP_FILTER_FLAG_TSYNC = 1

	// CLONE_NEWCGOUP is not included
	UnshareFlags = syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS |
		syscall.CLONE_NEWPID | syscall.CLONE_NEWUSER | syscall.CLONE_NEWUTS
)

// used by unshare remount / to private
var (
	none  = [...]byte{'n', 'o', 'n', 'e', 0}
	slash = [...]byte{'/', 0}

	// tmp dir made by pivot_root
	OldRoot = "old_root"
)
