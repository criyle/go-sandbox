package config

import (
	"fmt"
	"os"

	"github.com/criyle/go-sandbox/runner/ptrace"
)

// Handler defines file access restricted handler to call the ptrace
// safe runner
type Handler struct {
	SyscallAllow, SyscallTrace, Args []string
	FileSet                          *FileSets
	SyscallCounter                   SyscallCounter
	ShowDetails                      bool
}

// CheckRead checks whether the file have read permission
func (h *Handler) CheckRead(fn string) ptrace.TraceAction {
	if !h.FileSet.IsReadableFile(fn) {
		return h.onDgsFileDetect(fn)
	}
	return ptrace.TraceAllow
}

// CheckWrite checks whether the file have write permission
func (h *Handler) CheckWrite(fn string) ptrace.TraceAction {
	if !h.FileSet.IsWritableFile(fn) {
		return h.onDgsFileDetect(fn)
	}
	return ptrace.TraceAllow
}

// CheckStat checks whether the file have stat permission
func (h *Handler) CheckStat(fn string) ptrace.TraceAction {
	if !h.FileSet.IsStatableFile(fn) {
		return h.onDgsFileDetect(fn)
	}
	return ptrace.TraceAllow
}

// CheckSyscall checks syscalls other than allowed and traced agianst the
// SyscallCounter
func (h *Handler) CheckSyscall(syscallName string) ptrace.TraceAction {
	// if it is traced, then try to count syscall
	if inside, allow := h.SyscallCounter.Check(syscallName); inside {
		if allow {
			return ptrace.TraceAllow
		}
		return ptrace.TraceKill
	}
	// if it is traced but not counted, it should be soft banned
	return ptrace.TraceBan
}

// onDgsFileDetect soft ban file if in soft ban set
// otherwise stops the trace process
func (h *Handler) onDgsFileDetect(name string) ptrace.TraceAction {
	if h.FileSet.IsSoftBanFile(name) {
		return ptrace.TraceBan
	}
	h.print("Dangerous fileopen: ", name)
	return ptrace.TraceKill
}

// print is used to print debug information
func (h *Handler) print(v ...interface{}) {
	if h.ShowDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}
