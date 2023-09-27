//go:build linux && (mips64 || mips64le)

package container

import (
	"os"
	"syscall"
)

var signalToIgnore = []os.Signal{
	// signals that cause run-time panic
	syscall.SIGBUS, syscall.SIGFPE, syscall.SIGSEGV,
	// signals that cause the program to exit
	syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM,
	// signals that cause the program to exit with a stack dump
	syscall.SIGQUIT, syscall.SIGILL, syscall.SIGTRAP, syscall.SIGABRT, syscall.SIGSYS,
}
