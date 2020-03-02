package cgroup

import "testing"

func BenchmarkCgroup(b *testing.B) {
	builder, err := NewBuilder("benchmark").WithCPUAcct().WithMemory().WithPids().FilterByEnv()
	if err != nil {
		b.Error(err)
		return
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cg, err := builder.Build()
		if err != nil {
			b.Error(err)
			return
		}
		if err := cg.SetMemoryLimitInBytes(4096); err != nil {
			b.Error(err)
			return
		}
		if err := cg.SetPidsMax(1); err != nil {
			b.Error(err)
			return
		}
		if _, err := cg.CpuacctUsage(); err != nil {
			b.Error(err)
			return
		}
		if _, err := cg.MemoryMaxUsageInBytes(); err != nil {
			b.Error(err)
			return
		}
		cg.Destroy()
	}
}

func TestCgroup(t *testing.T) {
	builder, err := NewBuilder("test").WithCPUAcct().WithMemory().WithPids().FilterByEnv()
	if err != nil {
		t.Error(err)
		return
	}
	cg, err := builder.Build()
	if err != nil {
		t.Error(err)
		return
	}
	if err := cg.SetMemoryLimitInBytes(4096); err != nil {
		t.Error(err)
		return
	}
	if err := cg.SetPidsMax(1); err != nil {
		t.Error(err)
		return
	}
	if _, err := cg.CpuacctUsage(); err != nil {
		t.Error(err)
		return
	}
	if _, err := cg.MemoryMaxUsageInBytes(); err != nil {
		t.Error(err)
		return
	}
	cg.Destroy()
}
