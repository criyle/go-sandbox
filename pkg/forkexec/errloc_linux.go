package forkexec

import (
	"fmt"
	"syscall"
)

// ErrorLocation defines the location where child process failed to exec
type ErrorLocation int

// ChildError defines the specific error and location where it failed
type ChildError struct {
	Err      syscall.Errno
	Location ErrorLocation
	Index    int
}

// Location constants
const (
	LocClone ErrorLocation = iota + 1
	LocCloseWrite
	LocUnshareUserRead
	LocGetPid
	LocKeepCapability
	LocSetGroups
	LocSetGid
	LocSetUid
	LocDup3
	LocFcntl
	LocSetSid
	LocIoctl
	LocMountRoot
	LocMountTmpfs
	LocMountChdir
	LocMount
	LocMountMkdir
	LocPivotRoot
	LocUmount
	LocUnlink
	LocMountRootReadonly
	LocChdir
	LocSetRlimit
	LocSetNoNewPrivs
	LocDropCapability
	LocSetCap
	LocPtraceMe
	LocStop
	LocSeccomp
	LocSyncWrite
	LocSyncRead
	LocExecve
)

var locToString = []string{
	"unknown",
	"clone",
	"close_write",
	"unshare_user_read",
	"getpid",
	"keep_capability",
	"setgroups",
	"setgid",
	"setuid",
	"dup3",
	"fcntl",
	"setsid",
	"ioctl",
	"mount(root)",
	"mount(tmpfs)",
	"mount(chdir)",
	"mount",
	"mount(mkdir)",
	"pivot_root",
	"umount",
	"unlink",
	"mount(readonly)",
	"chdir",
	"setrlimt",
	"set_no_new_privs",
	"drop_capability",
	"set_cap",
	"ptrace_me",
	"stop",
	"seccomp",
	"sync_write",
	"sync_read",
	"execve",
}

func (e ErrorLocation) String() string {
	if e >= LocClone && e <= LocExecve {
		return locToString[e]
	}
	return "unknown"
}

func (e ChildError) Error() string {
	if e.Index > 0 {
		return fmt.Sprintf("%s(%d): %s", e.Location.String(), e.Index, e.Err.Error())
	}
	return fmt.Sprintf("%s: %s", e.Location.String(), e.Err.Error())
}
