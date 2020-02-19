// +build linux

package libseccomp

import (
	libseccomp "github.com/seccomp/libseccomp-golang"
)

// ToSyscallName convert syscallno to syscall name
func ToSyscallName(sysno uint) (string, error) {
	return libseccomp.ScmpSyscall(sysno).GetName()
}
