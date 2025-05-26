package mount

import (
	"os"
	"strings"
	"testing"
)

func TestBuilder_WithBind(t *testing.T) {
	b := NewBuilder().WithBind("/src", "/dst", true)
	if len(b.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(b.Mounts))
	}
	m := b.Mounts[0]
	if m.Source != "/src" || m.Target != "/dst" {
		t.Errorf("unexpected mount: %+v", m)
	}
	if !m.IsBindMount() {
		t.Errorf("expected bind mount")
	}
	if !m.IsReadOnly() {
		t.Errorf("expected readonly mount")
	}
}

func TestBuilder_WithTmpfs(t *testing.T) {
	b := NewBuilder().WithTmpfs("/tmp", "size=64m")
	if len(b.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(b.Mounts))
	}
	m := b.Mounts[0]
	if !m.IsTmpFs() {
		t.Errorf("expected tmpfs mount")
	}
	if m.Target != "/tmp" || m.Data != "size=64m" {
		t.Errorf("unexpected mount: %+v", m)
	}
}

func TestBuilder_WithProc(t *testing.T) {
	b := NewBuilder().WithProc()
	if len(b.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(b.Mounts))
	}
	m := b.Mounts[0]
	if m.FsType != "proc" {
		t.Errorf("expected proc fsType")
	}
	if !m.IsReadOnly() {
		t.Errorf("expected readonly proc mount")
	}
}

func TestBuilder_WithProcRW(t *testing.T) {
	b := NewBuilder().WithProcRW(true)
	if len(b.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(b.Mounts))
	}
	m := b.Mounts[0]
	if m.FsType != "proc" {
		t.Errorf("expected proc fsType")
	}
	if m.IsReadOnly() {
		t.Errorf("expected read-write proc mount")
	}
}

func TestBuilder_WithMounts(t *testing.T) {
	m1 := Mount{Source: "/a", Target: "/b"}
	m2 := Mount{Source: "/c", Target: "/d"}
	b := NewBuilder().WithMounts([]Mount{m1, m2})
	if len(b.Mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(b.Mounts))
	}
}

func TestBuilder_WithMount(t *testing.T) {
	m := Mount{Source: "/a", Target: "/b"}
	b := NewBuilder().WithMount(m)
	if len(b.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(b.Mounts))
	}
}

func TestBuilder_String(t *testing.T) {
	b := NewBuilder().
		WithBind("/src", "/dst", false).
		WithTmpfs("/tmp", "size=1m").
		WithProc()
	s := b.String()
	if !strings.HasPrefix(s, "Mounts: ") {
		t.Errorf("unexpected prefix: %q", s)
	}
	if !strings.Contains(s, "bind[/src:/dst:rw]") {
		t.Errorf("missing bind: %q", s)
	}
	if !strings.Contains(s, "tmpfs[/tmp]") {
		t.Errorf("missing tmpfs: %q", s)
	}
	if !strings.Contains(s, "proc[ro]") {
		t.Errorf("missing proc: %q", s)
	}
}

func TestBuilder_FilterNotExist(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFilePath := tmpDir + "/mounttest"
	f, err := os.Create(tmpFilePath)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	b := NewBuilder().
		WithBind(f.Name(), "/dst1", false).
		WithBind("/not/exist", "/dst2", false)
	b.FilterNotExist()
	if len(b.Mounts) != 1 {
		t.Errorf("expected 1 mount after filter, got %d", len(b.Mounts))
	}
	if b.Mounts[0].Source != f.Name() {
		t.Errorf("unexpected mount: %+v", b.Mounts[0])
	}
}
