package ptrace

import (
	"context"
	"os"

	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/ptracer"
	"github.com/criyle/go-sandbox/runner"
)

// Run starts the tracing process
func (r *Runner) Run(c context.Context) runner.Result {
	handler := r.Handler
	if handler == nil {
		handler = noopHandler{}
	}
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

		UnshareCgroupAfterSync: os.Getuid() == 0,
	}

	th := &tracerHandler{
		ShowDetails: r.ShowDetails,
		Unsafe:      r.Unsafe,
		Handler:     handler,
	}

	tracer := ptracer.Tracer{
		Handler: th,
		Runner:  ch,
		Limit:   r.Limit,
	}
	return tracer.Trace(c)
}

type noopHandler struct{}

func (noopHandler) CheckRead(string) ptracer.TraceAction    { return ptracer.TraceAllow }
func (noopHandler) CheckWrite(string) ptracer.TraceAction   { return ptracer.TraceAllow }
func (noopHandler) CheckStat(string) ptracer.TraceAction    { return ptracer.TraceAllow }
func (noopHandler) CheckSyscall(string) ptracer.TraceAction { return ptracer.TraceAllow }
