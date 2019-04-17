package tracer

import (
	"os"
	"syscall"

	secutil "github.com/criyle/go-judger/secutil"
	tracee "github.com/criyle/go-judger/tracee"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

const (
	msgDisallow int16 = iota + 1
	msgHandle
)

func (r *Tracer) buildFilter() (*libseccomp.ScmpFilter, error) {
	// make filter
	var defaultAction libseccomp.ScmpAction
	// if debug, allow all syscalls and output what was blocked
	if r.Unsafe || r.ShowDetails {
		defaultAction = libseccomp.ActTrace.SetReturnCode(msgDisallow)
	} else {
		defaultAction = libseccomp.ActKill
	}
	return secutil.BuildFilter(defaultAction, libseccomp.ActTrace.SetReturnCode(msgHandle), r.Allow, r.Trace)
}

// prepareFile opens file for new process
func (r *Tracer) prepareFiles() ([]*os.File, error) {
	var err error
	files := make([]*os.File, 3)
	if r.InputFileName != "" {
		files[0], err = os.OpenFile(r.InputFileName, os.O_RDONLY, 0755)
		if err != nil {
			goto openerror
		}
	}
	if r.OutputFileName != "" {
		files[1], err = os.OpenFile(r.OutputFileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0755)
		if err != nil {
			goto openerror
		}
	}
	if r.ErrorFileName != "" {
		files[2], err = os.OpenFile(r.ErrorFileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0755)
		if err != nil {
			goto openerror
		}
	}
	return files, nil
openerror:
	closeFiles(files)
	return nil, err
}

// closeFiles close all file in the list
func closeFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			f.Close()
		}
	}
}

func (r *Tracer) getTraceeRunner(bpf *syscall.SockFprog, fds []uintptr) tracee.Runner {
	tr := tracee.NewRunner()
	tr.RLimits = r.prepareRLimit()
	tr.WorkDir = r.WorkPath
	tr.BPF = bpf
	tr.Args = r.Args
	tr.Env = r.Env
	tr.Files = fds
	return tr
}

// prepareRLimit creates rlimit structures for tracee
func (r *Tracer) prepareRLimit() []tracee.RLimit {
	return []tracee.RLimit{
		// CPU limit
		{
			Res: syscall.RLIMIT_CPU,
			Rlim: syscall.Rlimit{
				Cur: r.TimeLimit,
				Max: r.RealTimeLimit,
			},
		},
		// File limit
		{
			Res: syscall.RLIMIT_FSIZE,
			Rlim: syscall.Rlimit{
				Cur: r.OutputLimit << 20,
				Max: r.OutputLimit << 20,
			},
		},
		// Stack limit
		{
			Res: syscall.RLIMIT_STACK,
			Rlim: syscall.Rlimit{
				Cur: r.StackLimit << 20,
				Max: r.StackLimit << 20,
			},
		},
	}
}
