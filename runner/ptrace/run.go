package ptrace

import (
	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/ptracer"
	"github.com/criyle/go-sandbox/types"
)

// Start starts the tracing process
func (r *Runner) Start(done <-chan struct{}) (<-chan types.Result, error) {
	ch := &forkexec.Runner{
		Args:     r.Args,
		Env:      r.Env,
		ExecFile: r.ExecFile,
		RLimits:  r.RLimits,
		Files:    r.Files,
		WorkDir:  r.WorkDir,
		Seccomp:  r.Seccomp.SockFprog(),
		Ptrace:   true,
		SyncFunc: r.SyncFunc,
	}

	th := &tracerHandler{
		ShowDetails: r.ShowDetails,
		Unsafe:      r.Unsafe,
		Handler:     r.Handler,
	}

	tracer := ptracer.Tracer{
		Handler: th,
		Runner:  ch,
		Limit:   r.Limit,
	}
	return tracer.Trace(done)
}
