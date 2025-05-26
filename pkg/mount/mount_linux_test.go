package mount

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestMount_IsBindMount(t *testing.T) {
	m := Mount{Flags: syscall.MS_BIND}
	if !m.IsBindMount() {
		t.Errorf("expected IsBindMount true")
	}
	m.Flags = 0
	if m.IsBindMount() {
		t.Errorf("expected IsBindMount false")
	}
}

func TestMount_IsReadOnly(t *testing.T) {
	m := Mount{Flags: syscall.MS_RDONLY}
	if !m.IsReadOnly() {
		t.Errorf("expected IsReadOnly true")
	}
	m.Flags = 0
	if m.IsReadOnly() {
		t.Errorf("expected IsReadOnly false")
	}
}

func TestMount_IsTmpFs(t *testing.T) {
	m := Mount{FsType: "tmpfs"}
	if !m.IsTmpFs() {
		t.Errorf("expected IsTmpFs true")
	}
	m.FsType = "other"
	if m.IsTmpFs() {
		t.Errorf("expected IsTmpFs false")
	}
}

func TestMount_String(t *testing.T) {
	tests := []struct {
		m    Mount
		want string
	}{
		{
			m:    Mount{Source: "/src", Target: "/dst", Flags: syscall.MS_BIND, FsType: "", Data: ""},
			want: "bind[/src:/dst:rw]",
		},
		{
			m:    Mount{Source: "/src", Target: "/dst", Flags: syscall.MS_BIND | syscall.MS_RDONLY, FsType: "", Data: ""},
			want: "bind[/src:/dst:ro]",
		},
		{
			m:    Mount{Source: "", Target: "/tmp", FsType: "tmpfs"},
			want: "tmpfs[/tmp]",
		},
		{
			m:    Mount{Source: "", Target: "proc", FsType: "proc", Flags: syscall.MS_RDONLY},
			want: "proc[ro]",
		},
		{
			m:    Mount{Source: "src", Target: "dst", FsType: "other", Flags: 0, Data: "data"},
			want: "mount[other,src:dst:0,data]",
		},
	}
	for _, tt := range tests {
		got := tt.m.String()
		if got != tt.want {
			t.Errorf("Mount.String() = %q, want %q", got, tt.want)
		}
	}
}

func TestEnsureMountTargetExists_Dir(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "foo/bar")
	err := ensureMountTargetExists(tmpDir, target)
	if err != nil {
		t.Fatalf("ensureMountTargetExists error: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat error: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("expected directory at %s", target)
	}
}

func TestEnsureMountTargetExists_File(t *testing.T) {
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "srcfile")
	if err := os.WriteFile(srcFile, []byte("x"), 0644); err != nil {
		t.Fatalf("write srcfile: %v", err)
	}
	target := filepath.Join(tmpDir, "targetfile")
	err := ensureMountTargetExists(srcFile, target)
	if err != nil {
		t.Fatalf("ensureMountTargetExists error: %v", err)
	}
	// Should be a file or at least exist
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("lstat error: %v", err)
	}
	if info.IsDir() {
		t.Errorf("expected file at %s, got directory", target)
	}
}
