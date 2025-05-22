package filehandler

import (
	"maps"
	"testing"
)

// Unit test for IsInSetSmart
func TestFileSet_IsInSetSmart(t *testing.T) {
	// Create a new FileSet
	fs := NewFileSet()

	// Add paths to the FileSet
	fs.Add("/path/to/file")
	fs.Add("/path/to/dir/")
	fs.Add("/path/to/dir/*")
	fs.Add("/")

	// Test cases
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Exact match", "/path/to/file", true},
		{"Directory match", "/path/to/dir", true},
		{"Wildcard match", "/path/to/dir/subfile", true},
		{"Root match", "/", true},
		{"Non-existent path", "/non/existent/path", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := fs.IsInSetSmart(test.input)
			if result != test.expected {
				t.Errorf("IsInSetSmart(%q) = %v; expected %v", test.input, result, test.expected)
			}
		})
	}
}

// Unit test for Add method
func TestFileSet_Add(t *testing.T) {
	// Create a new FileSet
	fs := NewFileSet()

	if fs.SystemRoot {
		t.Errorf("NewFileSet() failed; expected SystemRoot to be false")
	}

	// Test adding a path that is not the root directory
	fs.Add("/path/to/file")
	if fs.SystemRoot {
		t.Errorf("Add(\"/path/to/file\") failed; expected SystemRoot to be false")
	}

	// Test adding the root directory
	fs.Add("/")
	if !fs.SystemRoot {
		t.Errorf("Add(\"/\") failed; expected SystemRoot to be true")
	}

	// Test adding a regular path
	fs.Add("/path/to/file")
	if !fs.Set["/path/to/file"] {
		t.Errorf("Add(\"/path/to/file\") failed; expected path to be in the set")
	}

	// Test adding another path
	fs.Add("/another/path")
	if !fs.Set["/another/path"] {
		t.Errorf("Add(\"/another/path\") failed; expected path to be in the set")
	}

	// Test adding a path with a trailing slash
	fs.Add("/path/to/dir/")
	if !fs.Set["/path/to/dir/"] {
		t.Errorf("Add(\"/path/to/dir/\") failed; expected path to be in the set")
	}

	// Test adding a path with a wildcard
	fs.Add("/path/to/dir/*")
	if !fs.Set["/path/to/dir/*"] {
		t.Errorf("Add(\"/path/to/dir/*\") failed; expected path to be in the set")
	}

	// Test adding a relative path
	fs.Add("relative/path")
	if !fs.Set["relative/path"] {
		t.Errorf("Add(\"relative/path\") failed; expected path to be in the set")
	}
}

// Unit test for AddRange method
func TestFileSet_AddRange(t *testing.T) {
	// Create a new FileSet
	fs := NewFileSet()

	// Test cases
	tests := []struct {
		name       string
		paths      []string
		workPath   string
		expected   map[string]bool
		systemRoot bool
	}{
		{
			name:     "Add absolute paths",
			paths:    []string{"/path/to/file", "/another/path"},
			workPath: "/work/dir",
			expected: map[string]bool{
				"/path/to/file": true,
				"/another/path": true,
			},
			systemRoot: false,
		},
		{
			name:       "Add root directory",
			paths:      []string{"/"},
			workPath:   "/work/dir",
			expected:   map[string]bool{},
			systemRoot: true,
		},
		{
			name:     "Add relative paths",
			paths:    []string{"relative/path", "another/relative/path"},
			workPath: "/work/dir",
			expected: map[string]bool{
				"/work/dir/relative/path/":         true,
				"/work/dir/another/relative/path/": true,
			},
			systemRoot: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Reset the FileSet
			fs = NewFileSet()

			// Call AddRange
			fs.AddRange(test.paths, test.workPath)

			// Check SystemRoot
			if fs.SystemRoot != test.systemRoot {
				t.Errorf("SystemRoot = %v; expected %v", fs.SystemRoot, test.systemRoot)
			}

			// Check the Set
			if !maps.Equal(fs.Set, test.expected) {
				t.Errorf("Set = %v; expected %v", fs.Set, test.expected)
			}
		})
	}
}
