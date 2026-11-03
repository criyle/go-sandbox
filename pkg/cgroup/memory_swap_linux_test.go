//go:build linux

package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestV1MemorySwapLimitDisablesSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "memory.memsw.limit_in_bytes")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	cg := &V1{memory: newV1Controller(dir)}
	if err := cg.CheckMemorySwapLimit(); err != nil {
		t.Fatalf("check swap support: %v", err)
	}
	if err := cg.SetMemorySwapLimit(32); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "32" {
		t.Fatalf("memory.memsw.limit_in_bytes = %q, want 32", got)
	}
}

func TestV2MemorySwapLimitDisablesSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "memory.swap.max")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	cg := &V2{path: dir, control: &Controllers{Memory: true}}
	if err := cg.CheckMemorySwapLimit(); err != nil {
		t.Fatalf("check swap support: %v", err)
	}
	if err := cg.SetMemorySwapLimit(32); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "0" {
		t.Fatalf("memory.swap.max = %q, want 0", got)
	}
}
