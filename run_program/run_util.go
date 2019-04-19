package main

import (
	"os"
	"syscall"

	secutil "github.com/criyle/go-judger/secutil"
	tracee "github.com/criyle/go-judger/tracee"
	tracer "github.com/criyle/go-judger/tracer"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

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
	return secutil.BuildFilter(defaultAction, libseccomp.ActTrace.SetReturnCode(tracer.MsgHandle), allow, trace)
}

// prepareFile opens file for new process
func prepareFiles(inputFile, outputFile, errorFile string) ([]*os.File, error) {
	var err error
	files := make([]*os.File, 3)
	if inputFile != "" {
		files[0], err = os.OpenFile(inputFile, os.O_RDONLY, 0755)
		if err != nil {
			goto openerror
		}
	}
	if outputFile != "" {
		files[1], err = os.OpenFile(outputFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0755)
		if err != nil {
			goto openerror
		}
	}
	if errorFile != "" {
		files[2], err = os.OpenFile(errorFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0755)
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

func getRlimit(cur, max uint) syscall.Rlimit {
	return syscall.Rlimit{Cur: uint64(cur), Max: uint64(max)}
}

// prepareRLimit creates rlimit structures for tracee
// TimeLimit in s, SizeLimit in byte
func prepareRLimit(TimeLimit, RealTimeLimit, OutputLimit, StackLimit uint) []tracee.RLimit {
	return []tracee.RLimit{
		// CPU limit
		{
			Res:  syscall.RLIMIT_CPU,
			Rlim: getRlimit(TimeLimit, RealTimeLimit),
		},
		// File limit
		{
			Res:  syscall.RLIMIT_FSIZE,
			Rlim: getRlimit(OutputLimit, OutputLimit),
		},
		// Stack limit
		{
			Res:  syscall.RLIMIT_STACK,
			Rlim: getRlimit(StackLimit, StackLimit),
		},
	}
}
