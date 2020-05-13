package forkexec

import (
	"syscall"
)

// prepareExec prepares execve parameters
func prepareExec(Args, Env []string) (*byte, []*byte, []*byte, error) {
	// make exec args0
	argv0, err := syscall.BytePtrFromString(Args[0])
	if err != nil {
		return nil, nil, nil, err
	}
	// make exec args
	argv, err := syscall.SlicePtrFromStrings(Args)
	if err != nil {
		return nil, nil, nil, err
	}
	// make env
	env, err := syscall.SlicePtrFromStrings(Env)
	if err != nil {
		return nil, nil, nil, err
	}
	return argv0, argv, env, nil
}

// prepareFds prepares fd array
func prepareFds(files []uintptr) ([]int, int) {
	fd := make([]int, len(files))
	nextfd := len(files)
	for i, ufd := range files {
		if nextfd < int(ufd) {
			nextfd = int(ufd)
		}
		fd[i] = int(ufd)
	}
	nextfd++
	return fd, nextfd
}

// syscallStringFromString prepares *byte if string is not empty, other wise nil
func syscallStringFromString(str string) (*byte, error) {
	if str != "" {
		return syscall.BytePtrFromString(str)
	}
	return nil, nil
}
