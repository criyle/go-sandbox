package main

import (
	"log"
	"runtime"
	"time"

	tracee "github.com/criyle/go-judger/tracee"
	libseccomp "github.com/seccomp/libseccomp-golang"
	unix "golang.org/x/sys/unix"
)

var (
	defaultAllows = []string{
		"read",
		"write",
		"readv",
		"writev",
		"open",
		"unlink",
		"close",
		"readlink",
		"openat",
		"unlinkat",
		"readlinkat",
		"stat",
		"fstat",
		"lstat",
		"lseek",
		"access",
		"dup",
		"dup2",
		"dup3",
		"ioctl",
		"fcntl",

		"mmap",
		"mprotect",
		"munmap",
		"brk",
		"mremap",
		"msync",
		"mincore",
		"madvise",

		"rt_sigaction",
		"rt_sigprocmask",
		"rt_sigreturn",
		"rt_sigpending",
		"sigaltstack",

		"getcwd",

		"exit",
		"exit_group",

		"arch_prctl",

		"gettimeofday",
		"getrlimit",
		"getrusage",
		"times",
		"time",
		"clock_gettime",

		"restart_syscall",

		"execve",
	}
	defaultTraces = []string{
		//"execve",
	}
)

func buildFilter(allows, traces []string) (*libseccomp.ScmpFilter, error) {
	// make filter
	//filter, err := libseccomp.NewFilter(libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	filter, err := libseccomp.NewFilter(libseccomp.ActTrace.SetReturnCode(100))
	if err != nil {
		return nil, err
	}

	for _, s := range allows {
		//log.Println("[+] allow syscall: ", s)
		syscallID, err := libseccomp.GetSyscallFromName(s)
		if err != nil {
			return nil, err
		}
		filter.AddRule(syscallID, libseccomp.ActAllow)
	}

	for _, s := range traces {
		//log.Println("[+] trace syscall: ", s)
		syscallID, err := libseccomp.GetSyscallFromName(s)
		if err != nil {
			return nil, err
		}
		//filter.AddRule(syscallId, libseccomp.ActAllow)
		filter.AddRule(syscallID, libseccomp.ActTrace.SetReturnCode(10))
	}
	return filter, nil
}

func startTrace(args []string) {
	// Ptrace require running at the same thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	filter, err := buildFilter(defaultAllows, defaultTraces)
	if err != nil {
		log.Fatal("Failed to create filter: ", err)
	}
	r := tracee.NewRunner()
	r.Args = args
	r.Filter = filter

	// run in restricted mode
	pid, err := r.Start()
	if err != nil {
		log.Fatal("Failed to fork: ", err)
	}
	log.Println("After fork")

	unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACESECCOMP|unix.PTRACE_O_EXITKILL|
		unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_TRACEEXEC|
		unix.PTRACE_O_TRACEVFORK)

	// Set real time limit
	timer := time.AfterFunc(time.Duration(1e9), func() {
		log.Println("Before kill")
		unix.Kill(pid, unix.SIGKILL)
		log.Println("After kill")
	})
	defer timer.Stop()

	log.Println("Strart trace pid: ", pid)

	// trace unixs
	for {
		var wstatus unix.WaitStatus
		var rusage unix.Rusage

		_, err := unix.Wait4(pid, &wstatus, unix.WALL, &rusage)
		if err != nil {
			log.Fatalln("Wait4 fatal: ", err)
		}
		if wstatus.Exited() {
			log.Println("Exited", wstatus.ExitStatus())
			break
		}
		if wstatus.Signaled() {
			sig := wstatus.Signal()
			log.Println("Signal", sig)
			switch sig {
			case unix.SIGKILL:
				log.Println("Killed")
				break
			}
		}
		if wstatus.Stopped() {
			if wstatus.StopSignal() == unix.SIGTRAP {
				switch cause := wstatus.TrapCause(); cause {
				case unix.PTRACE_EVENT_SECCOMP:
					log.Println("Seccomp Traced")
					msg, err := unix.PtraceGetEventMsg(pid)
					if err != nil {
						log.Fatalln(err)
					}
					log.Println("Ptrace Event: ", msg)

				case unix.PTRACE_EVENT_CLONE:
					log.Println("Ptrace stop clone")

				case unix.PTRACE_EVENT_VFORK:
					log.Println("Ptrace stop vfork")

				case unix.PTRACE_EVENT_FORK:
					log.Println("Ptrace stop fork")

				case unix.PTRACE_EVENT_EXEC:
					log.Println("Ptrace stop exec")

				default:
					log.Println("Ptrace trap cause: ", cause, wstatus)
				}
			} else {
				log.Println("Ptrace stop signal: ", wstatus.StopSignal())
			}
		}

		log.Println("Ptrace continue")
		unix.PtraceCont(pid, 0)
	}
}
