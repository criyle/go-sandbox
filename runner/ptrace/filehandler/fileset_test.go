package filehandler

import "testing"

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
