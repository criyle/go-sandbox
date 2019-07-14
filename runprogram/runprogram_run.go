package runprogram

import (
	libseccomp "github.com/seccomp/libseccomp-golang"

	"github.com/criyle/go-judger/forkexec"
	"github.com/criyle/go-judger/seccomp"
	"github.com/criyle/go-judger/tracer"
)

// Start starts the tracing process
func (r *RunProgram) Start() (rt tracer.TraceResult, err error) {
	// build seccomp filter
	filter, err := buildFilter(r.ShowDetails, r.SyscallAllowed, r.SyscallTraced)
	if err != nil {
		println(err)
		return
	}
	defer filter.Release()

	bpf, err := seccomp.FilterToBPF(filter)
	if err != nil {
		println(err)
		return
	}

	ch := &forkexec.Runner{
		Args:    r.Args,
		Env:     r.Env,
		RLimits: r.RLimits.PrepareRLimit(),
		Files:   r.Files,
		WorkDir: r.WorkDir,
		Seccomp: bpf,
		Ptrace:  true,
	}

	th := &tracerHandler{
		ShowDetails: r.ShowDetails,
		Unsafe:      r.Unsafe,
		Handler:     r.Handler,
	}
	return tracer.Trace(th, ch, tracer.ResLimit(r.TraceLimit))
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
