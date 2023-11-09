package cgroup

import (
	"os"
	"testing"
)

func BenchmarkCgroup(b *testing.B) {
	if err := EnableV2Nesting(); err != nil {
		b.Fatal(err)
	}
	ct, err := GetAvailableControllerV2()
	if err != nil {
		b.Fatal(err)
	}
	builder, err := New("benchmark", ct)
	if err != nil {
		b.Fatal(err)
	}
	defer builder.Destroy()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cg, err := builder.New("test")
		if err != nil {
			b.Fatal(err)
		}
		if err := cg.SetCPUSet([]byte("0")); err != nil {
			b.Fatal(err)
		}
		if err := cg.SetMemoryLimit(4096); err != nil {
			b.Fatal(err)
		}
		if err := cg.SetProcLimit(1); err != nil {
			b.Fatal(err)
		}
		if _, err := cg.CPUUsage(); err != nil {
			b.Fatal(err)
		}
		if _, err := cg.MemoryMaxUsage(); err != nil {
			b.Fatal(err)
		}
		cg.Destroy()
	}
}

func TestCgroupAll(t *testing.T) {
	// ensure root privilege when testing
	if os.Getuid() != 0 {
		t.Skip("no root privilege")
	}
	if err := EnableV2Nesting(); err != nil {
		t.Fatal(err)
	}
	ct, err := GetAvailableControllerV2()
	if err != nil {
		t.Fatal(err)
	}
	builder, err := New("benchmark", ct)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	cg, err := builder.New("test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cg.Destroy()
	})
	if err := cg.SetCPUSet([]byte("0")); err != nil {
		t.Fatal(err)
	}
	if err := cg.SetMemoryLimit(4096); err != nil {
		t.Fatal(err)
	}
	if err := cg.SetProcLimit(1); err != nil {
		t.Fatal(err)
	}
	if _, err := cg.CPUUsage(); err != nil {
		t.Fatal(err)
	}
	if _, err := cg.MemoryMaxUsage(); err != nil {
		t.Fatal(err)
	}
}
