package ptrace

import (
	"syscall"
	"testing"

	"github.com/criyle/go-sandbox/ptracer"
)

type mockHandler struct {
	syscallAction ptracer.TraceAction
}

func (m mockHandler) CheckRead(string) ptracer.TraceAction {
	return ptracer.TraceAllow
}

func (m mockHandler) CheckWrite(string) ptracer.TraceAction {
	return ptracer.TraceAllow
}

func (m mockHandler) CheckStat(string) ptracer.TraceAction {
	return ptracer.TraceAllow
}

func (m mockHandler) CheckSyscall(string) ptracer.TraceAction {
	return m.syscallAction
}

func TestNormalizeProcMagicPath(t *testing.T) {
	const pid = 1234

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "self root",
			in:   "/proc/self",
			want: "/proc/1234",
		},
		{
			name: "self child",
			in:   "/proc/self/fd/0",
			want: "/proc/1234/fd/0",
		},
		{
			name: "thread self root",
			in:   "/proc/thread-self",
			want: "/proc/1234/task/1234",
		},
		{
			name: "thread self child",
			in:   "/proc/thread-self/fd/1",
			want: "/proc/1234/task/1234/fd/1",
		},
		{
			name: "cleaned non magic path",
			in:   "/tmp/../proc/self",
			want: "/proc/1234",
		},
		{
			name: "unrelated proc path",
			in:   "/proc/1/fd/0",
			want: "/proc/1/fd/0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeProcMagicPath(pid, tt.in); got != tt.want {
				t.Fatalf("normalizeProcMagicPath(%d, %q) = %q, want %q", pid, tt.in, got, tt.want)
			}
		})
	}
}

func TestIsAllowedProcAlias(t *testing.T) {
	const pid = 1234

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "self stdin", path: "/proc/self/fd/0", want: true},
		{name: "self stdout", path: "/proc/self/fd/1", want: true},
		{name: "thread self stderr", path: "/proc/thread-self/fd/2", want: true},
		{name: "tracee pid stdin", path: "/proc/1234/fd/0", want: true},
		{name: "tracee task stdout", path: "/proc/1234/task/1234/fd/1", want: true},
		{name: "tracee pid non stdio", path: "/proc/1234/fd/3", want: false},
		{name: "other pid stdio", path: "/proc/99/fd/0", want: false},
		{name: "other task stdio", path: "/proc/99/task/99/fd/1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAllowedProcAlias(pid, tt.path); got != tt.want {
				t.Fatalf("isAllowedProcAlias(%d, %q) = %v, want %v", pid, tt.path, got, tt.want)
			}
		})
	}
}

func TestIsDangerousProcPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "proc root", path: "/proc", want: false},
		{name: "non proc", path: "/tmp/file", want: false},
		{name: "self root only", path: "/proc/self", want: false},
		{name: "self fd", path: "/proc/self/fd/3", want: true},
		{name: "thread self namespace", path: "/proc/thread-self/ns/net", want: true},
		{name: "numeric pid fd", path: "/proc/1/fd/0", want: true},
		{name: "numeric pid cwd", path: "/proc/123/cwd", want: true},
		{name: "non numeric proc entry", path: "/proc/sys/kernel", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDangerousProcPath(tt.path); got != tt.want {
				t.Fatalf("isDangerousProcPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestCheckProcPath(t *testing.T) {
	const pid = 1234

	h := tracerHandler{
		Handler: mockHandler{syscallAction: ptracer.TraceBan},
	}

	tests := []struct {
		name        string
		path        string
		wantBlocked bool
		wantAction  ptracer.TraceAction
	}{
		{
			name:        "empty path",
			path:        "",
			wantBlocked: false,
			wantAction:  ptracer.TraceAllow,
		},
		{
			name:        "allowed stdio alias",
			path:        "/proc/1234/fd/0",
			wantBlocked: false,
			wantAction:  ptracer.TraceAllow,
		},
		{
			name:        "dangerous self fd",
			path:        "/proc/self/fd/3",
			wantBlocked: true,
			wantAction:  ptracer.TraceBan,
		},
		{
			name:        "dangerous numeric pid path",
			path:        "/proc/1/root/tmp/file",
			wantBlocked: true,
			wantAction:  ptracer.TraceBan,
		},
		{
			name:        "ordinary path",
			path:        "/tmp/file",
			wantBlocked: false,
			wantAction:  ptracer.TraceAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, action := h.checkProcPath(pid, tt.path)
			if blocked != tt.wantBlocked || action != tt.wantAction {
				t.Fatalf("checkProcPath(%d, %q) = (%v, %v), want (%v, %v)", pid, tt.path, blocked, action, tt.wantBlocked, tt.wantAction)
			}
		})
	}
}

func TestIsOpenReadOnly(t *testing.T) {
	tests := []struct {
		name  string
		flags uint64
		want  bool
	}{
		{name: "readonly", flags: syscall.O_RDONLY, want: true},
		{name: "writeonly", flags: syscall.O_WRONLY, want: false},
		{name: "readwrite", flags: syscall.O_RDWR, want: false},
		{name: "readonly create", flags: syscall.O_RDONLY | syscall.O_CREAT, want: false},
		{name: "readonly truncate", flags: syscall.O_RDONLY | syscall.O_TRUNC, want: false},
		{name: "readonly excl", flags: syscall.O_RDONLY | syscall.O_EXCL, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isOpenReadOnly(tt.flags); got != tt.want {
				t.Fatalf("isOpenReadOnly(%#x) = %v, want %v", tt.flags, got, tt.want)
			}
		})
	}
}
