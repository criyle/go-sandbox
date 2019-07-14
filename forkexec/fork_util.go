package forkexec

import (
	"syscall"

	"github.com/criyle/go-judger/mount"
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

// prepareMounts prepare mkdir and mount syscall params
func prepareMounts(ms []*mount.Mount) ([]*mount.SyscallParams, [][]*byte, error) {
	params, err := mount.ToSyscalls(ms)
	if err != nil {
		return nil, nil, err
	}
	// evaluate paths that need to be created
	pathsToCreate := make([][]*byte, 0, len(ms))
	for _, m := range ms {
		prefix := pathPrefix(m.Target)
		paths, err := arrayPtrFromStrings(prefix)
		if err != nil {
			return nil, nil, err
		}
		pathsToCreate = append(pathsToCreate, paths)
	}
	return params, pathsToCreate, nil
}

// pathPrefix get all components from path
func pathPrefix(path string) []string {
	ret := make([]string, 0)
	for i := 1; i < len(path); i++ {
		if path[i] == '/' {
			ret = append(ret, path[:i])
		}
	}
	ret = append(ret, path)
	return ret
}

// arrayPtrFromStrings convers srings to c style strings
func arrayPtrFromStrings(strs []string) ([]*byte, error) {
	bytes := make([]*byte, 0, len(strs))
	for _, s := range strs {
		b, err := syscall.BytePtrFromString(s)
		if err != nil {
			return nil, err
		}
		bytes = append(bytes, b)
	}
	return bytes, nil
}
