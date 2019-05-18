package main

import (
	"fmt"
	"os"

	"github.com/criyle/go-judger/runprogram"
)

type handler struct {
	fs          *fileSets
	sc          syscallCounter
	showDetails bool
}

func (h *handler) print(v ...interface{}) {
	if h.showDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}

func (h *handler) onDgsFileDetect(name string) runprogram.TraceAction {
	if h.fs.isSoftBanFile(name) {
		return runprogram.TraceBan
	}
	h.print("Dangerous fileopen: ", name)
	return runprogram.TraceKill
}

func (h *handler) CheckRead(fn string) runprogram.TraceAction {
	if !h.fs.isReadableFile(fn) {
		return h.onDgsFileDetect(fn)
	}
	return runprogram.TraceAllow
}

func (h *handler) CheckWrite(fn string) runprogram.TraceAction {
	if !h.fs.isWritableFile(fn) {
		return h.onDgsFileDetect(fn)
	}
	return runprogram.TraceAllow
}

func (h *handler) CheckStat(fn string) runprogram.TraceAction {
	if !h.fs.isStatableFile(fn) {
		return h.onDgsFileDetect(fn)
	}
	return runprogram.TraceAllow
}

func (h *handler) CheckSyscall(syscallName string) runprogram.TraceAction {
	// if it is traced, then try to count syscall
	if inside, allow := h.sc.check(syscallName); inside {
		if allow {
			return runprogram.TraceAllow
		}
		return runprogram.TraceKill
	}
	// if it is traced but not counted, it should be soft banned
	return runprogram.TraceBan
}
