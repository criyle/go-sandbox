package libseccomp

import (
	"fmt"

	"github.com/elastic/go-seccomp-bpf/arch"
)

var info, errInfo = arch.GetInfo("")

// ToSyscallName convert syscallno to syscall name
func ToSyscallName(sysno uint) (string, error) {
	if errInfo != nil {
		return "", errInfo
	}
	n, ok := info.SyscallNumbers[int(sysno)]
	if !ok {
		return "", fmt.Errorf("syscall number does not exist: %d", sysno)
	}
	return n, nil
}
