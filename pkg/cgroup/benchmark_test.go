package cgroup

import (
	"os"
	"testing"
)

func BenchmarkCgroup(b *testing.B) {
	builder, err := NewBuilder("benchmark").WithCPUSet().WithCPUAcct().WithMemory().WithPids().FilterByEnv()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cg, err := builder.Build()
		if err != nil {
			b.Fatal(err)
		}
		if err := cg.SetCpusetCpus([]byte("0")); err != nil {
			b.Fatal(err)
		}
		if err := cg.SetMemoryLimitInBytes(4096); err != nil {
			b.Fatal(err)
		}
		if err := cg.SetPidsMax(1); err != nil {
			b.Fatal(err)
		}
		if _, err := cg.CpuacctUsage(); err != nil {
			b.Fatal(err)
		}
		if _, err := cg.MemoryMaxUsageInBytes(); err != nil {
			b.Fatal(err)
		}
		cg.Destroy()
	}
}

func TestCgroupAll(t *testing.T) {
	// ensure root privillege when testing
	if os.Getuid() != 0 {
		t.Skip("no root privillege")
	}
	builder, err := NewBuilder("test").WithCPUSet().WithCPUAcct().WithMemory().WithPids().FilterByEnv()
	if err != nil {
		t.Fatal(err)
	}
	cg, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cg.Destroy()
	})
	if err := cg.SetCpusetCpus([]byte("0")); err != nil {
		t.Fatal(err)
	}
	if err := cg.SetMemoryLimitInBytes(4096); err != nil {
		t.Fatal(err)
	}
	if err := cg.SetPidsMax(1); err != nil {
		t.Fatal(err)
	}
	if _, err := cg.CpuacctUsage(); err != nil {
		t.Fatal(err)
	}
	if _, err := cg.MemoryMaxUsageInBytes(); err != nil {
		t.Fatal(err)
	}
}
