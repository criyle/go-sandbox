//go:build linux

package rlimit

import (
	"syscall"
	"testing"
)

func TestPrepareRLimit(t *testing.T) {
	tests := []struct {
		name   string
		rl     RLimits
		expect []int
	}{
		{
			name:   "Empty",
			rl:     RLimits{},
			expect: []int{},
		},
		{
			name:   "CPU only",
			rl:     RLimits{CPU: 1},
			expect: []int{syscall.RLIMIT_CPU},
		},
		{
			name:   "Data only",
			rl:     RLimits{Data: 1024},
			expect: []int{syscall.RLIMIT_DATA},
		},
		{
			name:   "All fields",
			rl:     RLimits{CPU: 1, CPUHard: 2, Data: 1024, FileSize: 2048, Stack: 4096, AddressSpace: 8192, OpenFile: 16, DisableCore: true},
			expect: []int{syscall.RLIMIT_CPU, syscall.RLIMIT_DATA, syscall.RLIMIT_FSIZE, syscall.RLIMIT_STACK, syscall.RLIMIT_AS, syscall.RLIMIT_NOFILE, syscall.RLIMIT_CORE},
		},
		{
			name:   "DisableCore only",
			rl:     RLimits{DisableCore: true},
			expect: []int{syscall.RLIMIT_CORE},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rls := tt.rl.PrepareRLimit()
			if len(rls) != len(tt.expect) {
				t.Fatalf("expected %d rlimits, got %d", len(tt.expect), len(rls))
			}
			for i, r := range rls {
				if r.Res != tt.expect[i] {
					t.Errorf("expected Res %d at %d, got %d", tt.expect[i], i, r.Res)
				}
			}
		})
	}
}

func TestRLimitString(t *testing.T) {
	tests := []struct {
		name string
		rl   RLimit
		want string
	}{
		{
			name: "CPU",
			rl:   RLimit{Res: syscall.RLIMIT_CPU, Rlim: syscall.Rlimit{Cur: 1, Max: 2}},
			want: "CPU[1 s:2 s]",
		},
		{
			name: "NOFILE",
			rl:   RLimit{Res: syscall.RLIMIT_NOFILE, Rlim: syscall.Rlimit{Cur: 10, Max: 20}},
			want: "OpenFile[10:20]",
		},
		{
			name: "DATA",
			rl:   RLimit{Res: syscall.RLIMIT_DATA, Rlim: syscall.Rlimit{Cur: 1024, Max: 2048}},
			want: "Data[1.0 KiB:2.0 KiB]",
		},
		{
			name: "FSIZE",
			rl:   RLimit{Res: syscall.RLIMIT_FSIZE, Rlim: syscall.Rlimit{Cur: 100, Max: 200}},
			want: "File[100 B:200 B]",
		},
		{
			name: "STACK",
			rl:   RLimit{Res: syscall.RLIMIT_STACK, Rlim: syscall.Rlimit{Cur: 4096, Max: 8192}},
			want: "Stack[4.0 KiB:8.0 KiB]",
		},
		{
			name: "AS",
			rl:   RLimit{Res: syscall.RLIMIT_AS, Rlim: syscall.Rlimit{Cur: 123, Max: 456}},
			want: "AddressSpace[123 B:456 B]",
		},
		{
			name: "CORE",
			rl:   RLimit{Res: syscall.RLIMIT_CORE, Rlim: syscall.Rlimit{Cur: 0, Max: 0}},
			want: "Core[0 B:0 B]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rl.String()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRLimitsString(t *testing.T) {
	rl := RLimits{
		CPU:          1,
		CPUHard:      2,
		Data:         1024,
		FileSize:     2048,
		Stack:        4096,
		AddressSpace: 8192,
		OpenFile:     16,
		DisableCore:  true,
	}
	want := "RLimits[CPU[1 s:2 s],Data[1.0 KiB:1.0 KiB],File[2.0 KiB:2.0 KiB],Stack[4.0 KiB:4.0 KiB],AddressSpace[8.0 KiB:8.0 KiB],OpenFile[16:16],Core[0 B:0 B]]"
	got := rl.String()
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRLimitsString_Empty(t *testing.T) {
	rl := RLimits{}
	want := "RLimits[]"
	got := rl.String()
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
