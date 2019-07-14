package forkexec

import (
	"golang.org/x/sys/unix"
)

// defines missing consts from syscall package
const (
	SECCOMP_SET_MODE_STRICT   = 0
	SECCOMP_SET_MODE_FILTER   = 1
	SECCOMP_FILTER_FLAG_TSYNC = 1

	// Unshare flags
	UnshareFlags = unix.CLONE_NEWIPC | unix.CLONE_NEWNET | unix.CLONE_NEWNS |
		unix.CLONE_NEWPID | unix.CLONE_NEWUSER | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP

	// Read-only bind mount need to be remounted
	bindRo = unix.MS_BIND | unix.MS_RDONLY
)

// used by unshare remount / to private
var (
	none  = [...]byte{'n', 'o', 'n', 'e', 0}
	slash = [...]byte{'/', 0}
	empty = [...]byte{0}
	tmpfs = [...]byte{'t', 'm', 'p', 'f', 's', 0}

	// tmp dir made by pivot_root
	OldRoot = "old_root"

	// go does not allow constant uintptr to be negative...
	_AT_FDCWD = unix.AT_FDCWD

	// Drop all capabilities
	dropCapHeader = unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0,
	}

	dropCapData = unix.CapUserData{
		Effective:   0,
		Permitted:   0,
		Inheritable: 0,
	}
)
