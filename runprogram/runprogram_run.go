package runprogram

import (
	libseccomp "github.com/seccomp/libseccomp-golang"

	"github.com/criyle/go-sandbox/forkexec"
	"github.com/criyle/go-sandbox/seccomp"
	"github.com/criyle/go-sandbox/tracer"
	"github.com/criyle/go-sandbox/types/specs"
)

// Start starts the tracing process
func (r *RunProgram) Start(done <-chan struct{}) (<-chan specs.TraceResult, error) {
	// build seccomp filter
	filter, err := buildFilter(r.ShowDetails, r.SyscallAllowed, r.SyscallTraced)
	if err != nil {
		println(err)
		return nil, err
	}
	defer filter.Release()

	bpf, err := seccomp.FilterToBPF(filter)
	if err != nil {
		println(err)
		return nil, err
	}

	ch := &forkexec.Runner{
		Args:     r.Args,
		Env:      r.Env,
		ExecFile: r.ExecFile,
		RLimits:  r.RLimits.PrepareRLimit(),
		Files:    r.Files,
		WorkDir:  r.WorkDir,
		Seccomp:  bpf,
		Ptrace:   true,
		SyncFunc: r.SyncFunc,
	}

	th := &tracerHandler{
		ShowDetails: r.ShowDetails,
		Unsafe:      r.Unsafe,
		Handler:     r.Handler,
	}
	return tracer.Trace(done, th, ch, specs.ResLimit(r.TraceLimit))
}

// build filter builds the libseccomp filter according to the allow, trace and show details
func buildFilter(showDetails bool, allow, trace []string) (*libseccomp.ScmpFilter, error) {
	// make filter
	var defaultAction libseccomp.ScmpAction
	// if debug, allow all syscalls and output what was blocked
	if showDetails {
		defaultAction = libseccomp.ActTrace.SetReturnCode(tracer.MsgDisallow)
	} else {
		defaultAction = libseccomp.ActKill
	}
	return seccomp.BuildFilter(defaultAction, libseccomp.ActTrace.SetReturnCode(tracer.MsgHandle), allow, trace)
}
