package forkexec

import (
	"syscall"
	"unsafe"
)

// SandboxInit calls sandbox_init
func SandboxInit(profile *byte, flags uint64, errorBuf **byte) (err error) {
	var r1 uintptr
	r1, _, err = syscall3(libc_sandbox_init_trampoline_addr, uintptr(unsafe.Pointer(profile)), uintptr(flags), uintptr(unsafe.Pointer(errorBuf)))
	if r1 != 0 {
		err = syscall.EINVAL
	} else {
		err = nil
	}
	return
}

// SandboxFreeError calls sandbox_free_error
func SandboxFreeError(errorBuf *byte) {
	syscall3(libc_sandbox_free_error_trampoline_addr, uintptr(unsafe.Pointer(errorBuf)), 0, 0)
}

var libc_sandbox_init_trampoline_addr uintptr

//go:cgo_import_dynamic libc_sandbox_init sandbox_init "/usr/lib/libSystem.B.dylib"

var libc_sandbox_free_error_trampoline_addr uintptr

//go:cgo_import_dynamic libc_sandbox_free_error sandbox_free_error "/usr/lib/libSystem.B.dylib"
