package ptrace

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/criyle/go-sandbox/pkg/seccomp/libseccomp"
	"github.com/criyle/go-sandbox/ptracer"
)

type tracerHandler struct {
	ShowDetails, Unsafe bool
	Handler             Handler
}

const atFDCWD = -100
const maxSymlinkDepth = 40

func (h *tracerHandler) Debug(v ...interface{}) {
	if h.ShowDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}

func (h *tracerHandler) getString(ctx *ptracer.Context, addr uint) string {
	return absPath(ctx.Pid, ctx.GetString(uintptr(addr)))
}

func (h *tracerHandler) getStringAt(ctx *ptracer.Context, dirfd int, addr uint) string {
	return absPathAt(ctx.Pid, dirfd, ctx.GetString(uintptr(addr)))
}

func (h *tracerHandler) checkOpen(ctx *ptracer.Context, addr uint, flags uint) ptracer.TraceAction {
	fn := h.getString(ctx, addr)
	if blocked, action := h.checkProcPath(ctx.Pid, fn); blocked {
		h.Debug("open proc policy: ", fn, getFileMode(flags))
		return action
	}
	isReadOnly := (flags&syscall.O_ACCMODE == syscall.O_RDONLY) &&
		(flags&syscall.O_CREAT == 0) &&
		(flags&syscall.O_EXCL == 0) &&
		(flags&syscall.O_TRUNC == 0)

	h.Debug("open: ", fn, getFileMode(flags))
	if isReadOnly {
		return h.Handler.CheckRead(fn)
	}
	return h.Handler.CheckWrite(fn)
}

func (h *tracerHandler) checkOpenAt(ctx *ptracer.Context, dirfd int, addr uint, flags uint) ptracer.TraceAction {
	fn := h.getStringAt(ctx, dirfd, addr)
	if blocked, action := h.checkProcPath(ctx.Pid, fn); blocked {
		h.Debug("openat proc policy: ", fn, getFileMode(flags), "dirfd:", dirfd)
		return action
	}
	isReadOnly := (flags&syscall.O_ACCMODE == syscall.O_RDONLY) &&
		(flags&syscall.O_CREAT == 0) &&
		(flags&syscall.O_EXCL == 0) &&
		(flags&syscall.O_TRUNC == 0)

	h.Debug("openat: ", fn, getFileMode(flags), "dirfd:", dirfd)
	if isReadOnly {
		return h.Handler.CheckRead(fn)
	}
	return h.Handler.CheckWrite(fn)
}

func (h *tracerHandler) checkRead(ctx *ptracer.Context, addr uint) ptracer.TraceAction {
	fn := h.getString(ctx, addr)
	if blocked, action := h.checkProcPath(ctx.Pid, fn); blocked {
		h.Debug("check read proc policy: ", fn)
		return action
	}
	h.Debug("check read: ", fn)
	return h.Handler.CheckRead(fn)
}

func (h *tracerHandler) checkReadAt(ctx *ptracer.Context, dirfd int, addr uint) ptracer.TraceAction {
	fn := h.getStringAt(ctx, dirfd, addr)
	if blocked, action := h.checkProcPath(ctx.Pid, fn); blocked {
		h.Debug("check read proc policy: ", fn, "dirfd:", dirfd)
		return action
	}
	h.Debug("check read: ", fn, "dirfd:", dirfd)
	return h.Handler.CheckRead(fn)
}

func (h *tracerHandler) checkWrite(ctx *ptracer.Context, addr uint) ptracer.TraceAction {
	fn := h.getString(ctx, addr)
	if blocked, action := h.checkProcPath(ctx.Pid, fn); blocked {
		h.Debug("check write proc policy: ", fn)
		return action
	}
	h.Debug("check write: ", fn)
	return h.Handler.CheckWrite(fn)
}

func (h *tracerHandler) checkWriteAt(ctx *ptracer.Context, dirfd int, addr uint) ptracer.TraceAction {
	fn := h.getStringAt(ctx, dirfd, addr)
	if blocked, action := h.checkProcPath(ctx.Pid, fn); blocked {
		h.Debug("check write proc policy: ", fn, "dirfd:", dirfd)
		return action
	}
	h.Debug("check write: ", fn, "dirfd:", dirfd)
	return h.Handler.CheckWrite(fn)
}

func (h *tracerHandler) checkStat(ctx *ptracer.Context, addr uint) ptracer.TraceAction {
	fn := h.getString(ctx, addr)
	if blocked, action := h.checkProcPath(ctx.Pid, fn); blocked {
		h.Debug("check stat proc policy: ", fn)
		return action
	}
	h.Debug("check stat: ", fn)
	return h.Handler.CheckStat(fn)
}

func (h *tracerHandler) checkStatAt(ctx *ptracer.Context, dirfd int, addr uint) ptracer.TraceAction {
	fn := h.getStringAt(ctx, dirfd, addr)
	if blocked, action := h.checkProcPath(ctx.Pid, fn); blocked {
		h.Debug("check stat proc policy: ", fn, "dirfd:", dirfd)
		return action
	}
	h.Debug("check stat: ", fn, "dirfd:", dirfd)
	return h.Handler.CheckStat(fn)
}

func (h *tracerHandler) Handle(ctx *ptracer.Context) ptracer.TraceAction {
	syscallNo := ctx.SyscallNo()
	syscallName, err := libseccomp.ToSyscallName(syscallNo)
	h.Debug("syscall:", syscallNo, syscallName, err)
	if err != nil {
		h.Debug("invalid syscall no")
		return ptracer.TraceKill
	}

	action := ptracer.TraceKill
	switch syscallName {
	case "open":
		action = h.checkOpen(ctx, ctx.Arg0(), ctx.Arg1())
	case "openat", "openat2":
		action = h.checkOpenAt(ctx, int(int64(ctx.Arg0())), ctx.Arg1(), ctx.Arg2())

	case "readlink":
		action = h.checkRead(ctx, ctx.Arg0())
	case "readlinkat":
		action = h.checkReadAt(ctx, int(int64(ctx.Arg0())), ctx.Arg1())

	case "unlink":
		action = h.checkWrite(ctx, ctx.Arg0())
	case "unlinkat":
		action = h.checkWriteAt(ctx, int(int64(ctx.Arg0())), ctx.Arg1())

	case "mkdirat", "mknodat", "symlinkat", "fchmodat", "fchmodat2":
		action = h.checkWriteAt(ctx, int(int64(ctx.Arg0())), ctx.Arg1())
	case "linkat":
		action = combineTraceActions(
			h.checkWriteAt(ctx, int(int64(ctx.Arg0())), ctx.Arg1()),
			h.checkWriteAt(ctx, int(int64(ctx.Arg2())), ctx.Arg3()),
		)
	case "renameat", "renameat2":
		action = combineTraceActions(
			h.checkWriteAt(ctx, int(int64(ctx.Arg0())), ctx.Arg1()),
			h.checkWriteAt(ctx, int(int64(ctx.Arg2())), ctx.Arg3()),
		)

	case "access":
		action = h.checkStat(ctx, ctx.Arg0())
	case "faccessat", "faccessat2":
		action = h.checkStatAt(ctx, int(int64(ctx.Arg0())), ctx.Arg1())

	case "stat", "stat64":
		action = h.checkStat(ctx, ctx.Arg0())
	case "lstat", "lstat64":
		action = h.checkStat(ctx, ctx.Arg0())
	case "statx", "fstatat", "fstatat64", "newfstatat":
		action = h.checkStatAt(ctx, int(int64(ctx.Arg0())), ctx.Arg1())

	case "execve":
		action = h.checkRead(ctx, ctx.Arg0())
	case "execveat":
		action = h.checkReadAt(ctx, int(int64(ctx.Arg0())), ctx.Arg1())

	case "chmod":
		action = h.checkWrite(ctx, ctx.Arg0())
	case "rename":
		action = h.checkWrite(ctx, ctx.Arg0())

	default:
		action = h.Handler.CheckSyscall(syscallName)
		if h.Unsafe && action == ptracer.TraceKill {
			action = ptracer.TraceBan
		}
	}

	switch action {
	case ptracer.TraceAllow:
		return ptracer.TraceAllow
	case ptracer.TraceBan:
		h.Debug("<soft ban syscall>")
		return softBanSyscall(ctx)
	default:
		return ptracer.TraceKill
	}
}

func softBanSyscall(ctx *ptracer.Context) ptracer.TraceAction {
	ctx.SetReturnValue(-int(BanRet))
	return ptracer.TraceBan
}

func combineTraceActions(actions ...ptracer.TraceAction) ptracer.TraceAction {
	combined := ptracer.TraceAllow
	for _, action := range actions {
		switch action {
		case ptracer.TraceKill:
			return ptracer.TraceKill
		case ptracer.TraceBan:
			combined = ptracer.TraceBan
		}
	}
	return combined
}

// checkProcPath applies an explicit policy for procfs object-reference aliases.
//
// Path-based sandbox checks become very weak for procfs references such as
// /proc/self/fd/*, /proc/self/root/*, /proc/self/cwd/* and task-specific
// variants because they are indirections to already-open objects or alternate
// namespace views. To keep common Unix stdio aliases working, we allow only
// the tracee's own stdin/stdout/stderr fd aliases and deny the broader procfs
// classes by default before consulting the file allowlists.
func (h *tracerHandler) checkProcPath(pid int, path string) (bool, ptracer.TraceAction) {
	if path == "" {
		return false, ptracer.TraceAllow
	}
	if isAllowedProcAlias(pid, path) {
		return false, ptracer.TraceAllow
	}
	if isDangerousProcPath(path) {
		return true, h.Handler.CheckSyscall("procfs-path")
	}
	return false, ptracer.TraceAllow
}

func getFileMode(flags uint) string {
	switch flags & syscall.O_ACCMODE {
	case syscall.O_RDONLY:
		return "r "
	case syscall.O_WRONLY:
		return "w "
	case syscall.O_RDWR:
		return "wr"
	default:
		return "??"
	}
}

// getProcCwd gets the process CWD
func getProcCwd(pid int) string {
	fileName := "/proc/self/cwd"
	if pid > 0 {
		fileName = fmt.Sprintf("/proc/%d/cwd", pid)
	}
	s, err := os.Readlink(fileName)
	if err != nil {
		return ""
	}
	return s
}

func getProcFd(pid int, fd int) string {
	fileName := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	s, err := os.Readlink(fileName)
	if err != nil {
		return ""
	}
	return resolveTraceePath(pid, "/", normalizeProcMagicPath(pid, s))
}

// absPath calculates the absolute path for a process
// built-in function did the dirty works to resolve relative paths
func absPath(pid int, p string) string {
	// if relative path
	if !filepath.IsAbs(p) {
		return resolveTraceePath(pid, getProcCwd(pid), p)
	}
	return resolveTraceePath(pid, "/", p)
}

func absPathAt(pid int, dirfd int, p string) string {
	if filepath.IsAbs(p) {
		return resolveTraceePath(pid, "/", p)
	}
	if dirfd == atFDCWD {
		return resolveTraceePath(pid, getProcCwd(pid), p)
	}
	base := getProcFd(pid, dirfd)
	if base == "" {
		return ""
	}
	return resolveTraceePath(pid, base, p)
}

func normalizeProcMagicPath(pid int, p string) string {
	p = filepath.Clean(p)
	traceeProc := "/proc/" + strconv.Itoa(pid)

	switch {
	case p == "/proc/self":
		return traceeProc
	case strings.HasPrefix(p, "/proc/self/"):
		return filepath.Join(traceeProc, strings.TrimPrefix(p, "/proc/self/"))
	case p == "/proc/thread-self":
		// Best-effort normalization: for single-threaded checks, map thread-self to the tracee task path.
		return filepath.Join(traceeProc, "task", strconv.Itoa(pid))
	case strings.HasPrefix(p, "/proc/thread-self/"):
		return filepath.Join(traceeProc, "task", strconv.Itoa(pid), strings.TrimPrefix(p, "/proc/thread-self/"))
	default:
		return p
	}
}

func isAllowedProcAlias(pid int, path string) bool {
	traceePID := strconv.Itoa(pid)
	switch path {
	case "/proc/self/fd/0", "/proc/self/fd/1", "/proc/self/fd/2":
		return true
	case "/proc/thread-self/fd/0", "/proc/thread-self/fd/1", "/proc/thread-self/fd/2":
		return true
	case "/proc/" + traceePID + "/fd/0", "/proc/" + traceePID + "/fd/1", "/proc/" + traceePID + "/fd/2":
		return true
	case "/proc/" + traceePID + "/task/" + traceePID + "/fd/0",
		"/proc/" + traceePID + "/task/" + traceePID + "/fd/1",
		"/proc/" + traceePID + "/task/" + traceePID + "/fd/2":
		return true
	default:
		return false
	}
}

func isDangerousProcPath(path string) bool {
	path = filepath.Clean(path)
	if path == "/proc" {
		return false
	}
	if !strings.HasPrefix(path, "/proc/") {
		return false
	}

	rest := strings.TrimPrefix(path, "/proc/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 {
		return false
	}

	switch parts[0] {
	case "self", "thread-self":
		if len(parts) == 1 {
			return false
		}
		switch parts[1] {
		case "fd", "fdinfo", "root", "cwd", "task", "ns", "map_files", "mem":
			return true
		default:
			return false
		}
	default:
		// Any numeric /proc/<pid>/... path is treated as dangerous because it
		// exposes other-task object references and alternate views of the FS.
		if _, err := strconv.Atoi(parts[0]); err == nil {
			return true
		}
		return false
	}
}

func resolveTraceePath(pid int, base string, p string) string {
	p = normalizeProcMagicPath(pid, p)
	if !filepath.IsAbs(p) {
		if base == "" {
			base = getProcCwd(pid)
		}
		p = filepath.Join(base, p)
	}
	p = filepath.Clean(p)

	for range maxSymlinkDepth {
		next, changed := resolveTraceePathOnce(pid, p)
		if !changed {
			return next
		}
		p = next
	}
	return p
}

func resolveTraceePathOnce(pid int, p string) (string, bool) {
	if p == "/" {
		return p, false
	}

	cur := "/"
	rest := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, part := range rest {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			cur = filepath.Dir(cur)
			if cur == "." {
				cur = "/"
			}
			continue
		}

		candidate := filepath.Join(cur, part)
		lstatPath := filepath.Join(fmt.Sprintf("/proc/%d/root", pid), candidate)
		fi, err := os.Lstat(lstatPath)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			cur = candidate
			continue
		}

		target, err := os.Readlink(lstatPath)
		if err != nil {
			cur = candidate
			continue
		}
		target = normalizeProcMagicPath(pid, target)
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(candidate), target)
		}
		target = filepath.Clean(target)

		if i+1 < len(rest) {
			target = filepath.Join(target, filepath.Join(rest[i+1:]...))
		}
		return filepath.Clean(target), true
	}
	return filepath.Clean(cur), false
}
