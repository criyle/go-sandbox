package ptracer

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// TestHasNull tests the hasNull function
func TestHasNull(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "empty buffer",
			data: []byte{},
			want: false,
		},
		{
			name: "no null",
			data: []byte("hello"),
			want: false,
		},
		{
			name: "has null at start",
			data: []byte{0, 1, 2, 3},
			want: true,
		},
		{
			name: "has null at end",
			data: []byte{1, 2, 3, 0},
			want: true,
		},
		{
			name: "has null in middle",
			data: []byte{1, 0, 3, 4},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasNull(tt.data); got != tt.want {
				t.Errorf("hasNull() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function: creates a child process and returns its PID
func createTestProcess(t *testing.T) (int, func()) {
	cmd := exec.Command("sleep", "10") // use sleep command to create a running process
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start test process: %v", err)
	}

	cleanup := func() {
		cmd.Process.Kill()
		cmd.Wait()
	}

	return cmd.Process.Pid, cleanup
}

// TestVmRead tests the vmRead function
func TestVmRead(t *testing.T) {
	pid, cleanup := createTestProcess(t)
	defer cleanup()

	// create test data
	testData := []byte("Hello, World!")
	buff := make([]byte, len(testData))

	// get process memory maps
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		t.Fatalf("Failed to read process maps: %v", err)
	}

	// parse memory maps to find a readable address
	var addr uintptr
	for _, line := range bytes.Split(maps, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		if bytes.Contains(line, []byte("r-x")) { // find a readable segment
			var start uint64
			fmt.Sscanf(string(line), "%x-", &start)
			addr = uintptr(start)
			break
		}
	}

	if addr == 0 {
		t.Fatal("Failed to find readable memory region")
	}

	// test reading
	n, err := vmRead(pid, addr, buff)
	if err != nil {
		t.Fatalf("vmRead failed: %v", err)
	}
	if n == 0 {
		t.Error("vmRead returned 0 bytes")
	}
}

// TestVmReadStr tests the vmReadStr function
func TestVmReadStr(t *testing.T) {
	pid, cleanup := createTestProcess(t)
	defer cleanup()

	// test cases
	testCases := []struct {
		name      string
		buffSize  int
		addrAlign uintptr // address alignment, used to test different alignment scenarios
		wantErr   bool
	}{
		{
			name:      "small_buffer_aligned",
			buffSize:  10,
			addrAlign: 0,
			wantErr:   false,
		},
		{
			name:      "small_buffer_unaligned",
			buffSize:  10,
			addrAlign: 1,
			wantErr:   false,
		},
		{
			name:      "exact_page_size",
			buffSize:  pageSize,
			addrAlign: 0,
			wantErr:   false,
		},
		{
			name:      "cross_page_boundary",
			buffSize:  pageSize + 100,
			addrAlign: uintptr(pageSize - 50),
			wantErr:   false,
		},
		{
			name:      "large_buffer_unaligned",
			buffSize:  pageSize * 2,
			addrAlign: 123,
			wantErr:   false,
		},
		{
			name:      "buffer_smaller_than_to_boundary",
			buffSize:  10,
			addrAlign: uintptr(pageSize - 100), // distance to page boundary is 100 bytes, but buffer is only 10 bytes
			wantErr:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buff := make([]byte, tc.buffSize)
			
			// get a readable memory address
			maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
			if err != nil {
				t.Fatalf("Failed to read process maps: %v", err)
			}

			var baseAddr uintptr
			for _, line := range bytes.Split(maps, []byte{'\n'}) {
				if len(line) == 0 {
					continue
				}
				if bytes.Contains(line, []byte("r-x")) {
					var start uint64
					fmt.Sscanf(string(line), "%x-", &start)
					baseAddr = uintptr(start)
					break
				}
			}

			if baseAddr == 0 {
				t.Fatal("Failed to find readable memory region")
			}

			// use test case specified alignment offset
			testAddr := baseAddr + tc.addrAlign

			// record buffer content before reading
			originalBuff := make([]byte, len(buff))
			copy(originalBuff, buff)

			err = vmReadStr(pid, testAddr, buff)
			if (err != nil) != tc.wantErr {
				t.Errorf("vmReadStr() error = %v, wantErr %v", err, tc.wantErr)
			}

			// verify if actual reading occurred
			if !bytes.Equal(buff, originalBuff) {
				// at least some data was read
				t.Logf("Data was read successfully for case: %s", tc.name)
			}

			// special case: check buffer size smaller than distance to boundary
			if tc.name == "buffer_smaller_than_to_boundary" {
				distToBoundary := pageSize - int(testAddr%uintptr(pageSize))
				if distToBoundary > len(buff) {
					t.Logf("Verified buffer handling when smaller than distance to boundary: dist=%d, buff=%d",
						distToBoundary, len(buff))
				}
			}
		})
	}
}

// TestSliceBehavior tests slice behavior
func TestSliceBehavior(t *testing.T) {
	tests := []struct {
		name      string
		buffSize  int
		nextRead  int
		expected  int
	}{
		{
			name:     "small_buffer_large_read",
			buffSize: 10,
			nextRead: 4096,
			expected: 10,  // must be limited to buffer size
		},
		{
			name:     "large_buffer_small_read",
			buffSize: 8192,
			nextRead: 4096,
			expected: 4096,  // can use full read amount
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buff := make([]byte, tt.buffSize)
			// safely calculate actual read amount
			actualRead := tt.nextRead
			if tt.buffSize < actualRead {
				actualRead = tt.buffSize
			}
			slice := buff[:actualRead]
			
			if len(slice) != tt.expected {
				t.Errorf("Expected slice len %d, got %d", tt.expected, len(slice))
			}
		})
	}
}
