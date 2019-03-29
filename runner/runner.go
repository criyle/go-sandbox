package main

import (
	libseccomp "github.com/seccomp/libseccomp-golang"
)

// ProgramRunner is the RunProgramConfig
// including the exec path, argv
// and resource limits
type ProgramRunner struct {
	// Resource limit set by set rlimit
	TimeLimit     uint64 // second
	RealTimeLimit uint64 // second
	MemoryLimit   uint64 // mb
	OutputLimit   uint64 // mb
	StackLimit    uint64 // mb

	// stdin, stdout, stderr file name. nil for default
	InputFileName  string
	OutputFileName string
	ErrorFileName  string

	// work path
	WorkPath string

	// argv and env for the child process
	Args []string
	Env  []string

	// libseccomp Filter applied to child
	Filter *libseccomp.ScmpFilter
}

// NewProgramRunner creates program config with default setting
func NewProgramRunner() ProgramRunner {
	return ProgramRunner{
		TimeLimit:     1,
		RealTimeLimit: 0,
		MemoryLimit:   256,
		OutputLimit:   64,
		StackLimit:    1024,
	}
}

func (r *ProgramRunner) verify() {
	if r.RealTimeLimit < r.TimeLimit {
		r.RealTimeLimit = r.TimeLimit + 2
	}
	if r.StackLimit > r.MemoryLimit {
		r.StackLimit = r.MemoryLimit
	}
}
