package forkexec

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Start will fork, load seccomp and execve and being traced by ptrace
// Return pid and potential error
// The runtime OS thread must be locked before calling this function
// if ptrace is set to true
func (r *Runner) Start() (int, error) {
	argv0, argv, env, err := prepareExec(r.Args, r.Env)
	if err != nil {
		return 0, err
	}

	// prepare work dir
	workdir, err := syscallStringFromString(r.WorkDir)
	if err != nil {
		return 0, err
	}

	// prepare sandbox profile
	profile, err := syscallStringFromString(r.SandboxProfile)
	if err != nil {
		return 0, err
	}

	// ensure the socketpair created did not leak to child
	syscall.ForkLock.Lock()

	// socketpair p is also used to sync with parent before final execve
	// p[0] is used by parent and p[1] is used by child
	var p [2]int
	if err := forkExecSocketPair(&p); err != nil {
		syscall.ForkLock.Unlock()
		return 0, err
	}

	// fork in child
	pid, err1 := forkAndExecInChild(r, argv0, argv, env, workdir, profile, p)

	// restore all signals
	afterFork()

	syscall.ForkLock.Unlock()

	return syncWithChild(r, p, int(pid), err1)
}

func forkExecSocketPair(p *[2]int) error {
	var err error
	*p, err = syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	_, err = fcntl(p[0], syscall.F_SETFD, syscall.FD_CLOEXEC)
	if err != nil {
		return err
	}
	_, err = fcntl(p[1], syscall.F_SETFD, syscall.FD_CLOEXEC)
	if err != nil {
		return err
	}
	return nil
}

func syncWithChild(r *Runner, p [2]int, pid int, err1 syscall.Errno) (int, error) {
	var (
		r1   uintptr
		err2 syscall.Errno
		err  error
	)

	// sync with child
	unix.Close(p[1])

	// clone syscall failed
	if err1 != 0 {
		unix.Close(p[0])
		return 0, syscall.Errno(err1)
	}
	r1, _, err1 = syscall3(libc_read_trampoline_addr, uintptr(p[0]), uintptr(unsafe.Pointer(&err2)), uintptr(unsafe.Sizeof(err2)))
	// child returned error code
	if r1 != unsafe.Sizeof(err2) || err2 != 0 || err1 != 0 {
		err = handlePipeError(r1, err2)
		goto fail
	}

	// if syncfunc return error, then fail child immediately
	if r.SyncFunc != nil {
		if err = r.SyncFunc(int(pid)); err != nil {
			goto fail
		}
	}
	// otherwise, ack child (err1 == 0)
	r1, _, err1 = syscall3(libc_write_trampoline_addr, uintptr(p[0]), uintptr(unsafe.Pointer(&err1)), uintptr(unsafe.Sizeof(err1)))
	if err1 != 0 {
		goto fail
	}

	// if read anything mean child failed after sync (close_on_exec so it should not block)
	r1, _, err1 = syscall3(libc_read_trampoline_addr, uintptr(p[0]), uintptr(unsafe.Pointer(&err2)), uintptr(unsafe.Sizeof(err2)))
	unix.Close(p[0])
	if r1 != 0 || err1 != 0 {
		err = handlePipeError(r1, err2)
		goto failAfterClose
	}
	return int(pid), nil

fail:
	unix.Close(p[0])

failAfterClose:
	handleChildFailed(int(pid))
	return 0, err
}

// check pipe error
func handlePipeError(r1 uintptr, errno syscall.Errno) error {
	if r1 == unsafe.Sizeof(errno) {
		return syscall.Errno(errno)
	}
	return syscall.EPIPE
}

func handleChildFailed(pid int) {
	var wstatus syscall.WaitStatus
	// make sure not blocked
	syscall.Kill(pid, syscall.SIGKILL)
	// child failed; wait for it to exit, to make sure the zombies don't accumulate
	_, err := syscall.Wait4(pid, &wstatus, 0, nil)
	for err == syscall.EINTR {
		_, err = syscall.Wait4(pid, &wstatus, 0, nil)
	}
}
