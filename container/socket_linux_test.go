package container

import (
	"fmt"
	"os"
	"testing"
)

func init() {
	Init()
}

func TestManyFilesOpen(t *testing.T) {
	m := getEnv(t, nil)

	tests := []struct {
		name  string
		count int
	}{
		{"Small", 10},
		{"Medium", 100},
		{"BatchBoundary", 200},
		{"OverBatch-300", 300},
		{"Large-500", 500},
		{"Large-1000", 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmds := make([]OpenCmd, tt.count)
			for i := 0; i < tt.count; i++ {
				cmds[i] = OpenCmd{
					Path:     fmt.Sprintf("/w/test_%s_%d", tt.name, i),
					Flag:     os.O_CREATE | os.O_WRONLY | os.O_TRUNC,
					Perm:     0644,
					MkdirAll: true,
				}
			}
			results, err := m.Open(cmds)
			if err != nil {
				t.Fatalf("Open(%d files): %v", tt.count, err)
			}
			if len(results) != tt.count {
				t.Fatalf("got %d results, want %d", len(results), tt.count)
			}
			successCount := 0
			for i, r := range results {
				if r.Err != nil {
					t.Errorf("result[%d]: %v", i, r.Err)
					continue
				}
				if r.File == nil {
					t.Errorf("result[%d]: File is nil", i)
					continue
				}
				r.File.Close()
				successCount++
			}
			t.Logf("successfully opened %d/%d files", successCount, tt.count)
		})
	}
}

func TestLongPathsManyFiles(t *testing.T) {
	m := getEnv(t, nil)

	n := 200
	longPathPrefix := "/w/very_long_directory_name_to_increase_gob_payload_size/subdir_level2/another_level"
	cmds := make([]OpenCmd, n)
	for i := 0; i < n; i++ {
		cmds[i] = OpenCmd{
			Path:     fmt.Sprintf("%s/file_number_%d_with_some_extra_padding_to_make_it_even_longer", longPathPrefix, i),
			Flag:     os.O_CREATE | os.O_WRONLY | os.O_TRUNC,
			Perm:     0644,
			MkdirAll: true,
		}
	}
	results, err := m.Open(cmds)
	if err != nil {
		t.Fatalf("Open with long paths: %v", err)
	}
	if len(results) != n {
		t.Fatalf("got %d results, want %d", len(results), n)
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d]: %v", i, r.Err)
			continue
		}
		if r.File != nil {
			r.File.Close()
		}
	}
}

func TestOpenThenExecveManyFiles(t *testing.T) {
	m := getEnv(t, nil)

	// Open many files
	n := 500
	cmds := make([]OpenCmd, n)
	for i := 0; i < n; i++ {
		cmds[i] = OpenCmd{
			Path:     fmt.Sprintf("/w/exectest_%d", i),
			Flag:     os.O_CREATE | os.O_WRONLY | os.O_TRUNC,
			Perm:     0644,
			MkdirAll: true,
		}
	}
	results, err := m.Open(cmds)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, r := range results {
		if r.File != nil {
			r.File.Close()
		}
	}

	// Verify container still works after many opens
	if err := m.Ping(); err != nil {
		t.Fatalf("Ping after many opens: %v", err)
	}
}

func TestMixedSuccessFailure(t *testing.T) {
	m := getEnv(t, nil)

	cmds := []OpenCmd{
		{Path: "/w/valid1", Flag: os.O_CREATE | os.O_WRONLY, Perm: 0644},
		{Path: "/root/invalid_no_permission", Flag: os.O_CREATE | os.O_WRONLY, Perm: 0644},
		{Path: "/w/valid2", Flag: os.O_CREATE | os.O_WRONLY, Perm: 0644},
	}
	results, err := m.Open(cmds)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if results[0].Err != nil {
		t.Errorf("valid1 should succeed: %v", results[0].Err)
	} else if results[0].File != nil {
		results[0].File.Close()
	}
	if results[1].Err == nil {
		t.Error("invalid path should fail")
	}
	if results[2].Err != nil {
		t.Errorf("valid2 should succeed: %v", results[2].Err)
	} else if results[2].File != nil {
		results[2].File.Close()
	}
}
