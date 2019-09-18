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
	envv, err := syscall.SlicePtrFromStrings(Env)
	if err != nil {
		return nil, nil, nil, err
	}
	return argv0, argv, envv, nil
}

// prepareFds prapares fd array
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

// preparePivotRoot prepares pivot root parameters
func preparePivotRoot(r string) (*byte, *byte, error) {
	if r == "" {
		return nil, nil, nil
	}
	root, err := syscall.BytePtrFromString(r)
	if err != nil {
		return nil, nil, err
	}
	oldRoot, err := syscall.BytePtrFromString(OldRoot)
	if err != nil {
		return nil, nil, err
	}
	return root, oldRoot, nil
}
