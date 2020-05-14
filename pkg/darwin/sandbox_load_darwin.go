package darwin

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

func goString(b *byte) string {
	l := 0
	sb := (*[1 << 20]byte)(unsafe.Pointer(b))
	for sb[l] > 0 {
		l++
	}
	return string(sb[: l-1 : l-1])
}

// SandboxLoadProfile loads profile by sandbox_init
func SandboxLoadProfile(profile string) (err error) {
	var errBuf *byte
	p, err := syscall.BytePtrFromString(profile)
	if err != nil {
		return
	}
	if err := SandboxInit(p, 0, &errBuf); err != nil {
		defer SandboxFreeError(errBuf)
		if errBuf != nil {
			s := goString(errBuf)
			return os.NewSyscallError("sandbox_init", errors.New(s))
		}
		return os.NewSyscallError("sandbox_init", err)
	}
	return
}
