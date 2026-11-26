package container

import (
	"context"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/criyle/go-sandbox/pkg/mount"
	"github.com/criyle/go-sandbox/runner"
)

func execWithOutput(t *testing.T, m Environment, script string) (runner.Result, string) {
	t.Helper()

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()

	out, err := os.CreateTemp("", "ipc-output")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(out.Name())
	defer out.Close()

	r := m.Execve(context.TODO(), ExecveParam{
		Args:  []string{"/bin/sh", "-c", script},
		Env:   []string{"PATH=/usr/bin:/bin"},
		Files: []uintptr{devNull.Fd(), out.Fd(), out.Fd()},
	})
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	return r, string(content)
}

// TestIPCIsolationPerExec verifies that SysV IPC objects created by one exec
// are not visible to a later exec that reuses the same container, while
// processes forked within one exec still share the same IPC namespace.
func TestIPCIsolationPerExec(t *testing.T) {
	if _, err := exec.LookPath("ipcmk"); err != nil {
		t.Skip("ipcmk is required for this test")
	}

	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Remove(tmpDir)
	})

	mounts := mount.NewDefaultBuilder().
		WithProc().
		WithTmpfs("w", "").
		WithTmpfs("tmp", "").
		FilterNotExist().Mounts

	m, err := (&Builder{
		Root:   tmpDir,
		Mounts: mounts,
		Stderr: os.Stderr,
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.Destroy()
	})

	// The first exec creates a segment and checks it from a child process.
	// This guards against breaking IPC sharing between processes that belong
	// to the same exec (e.g. parent/child or MPI-style workloads).
	create, createOut := execWithOutput(t, m,
		`ipcmk -M 4096 && wc -l < /proc/sysvipc/shm && test "$(wc -l < /proc/sysvipc/shm)" -gt 1`)
	if create.Status != runner.StatusNormal {
		t.Fatalf("create ipc: %v %v output=%q", create.Status, create.Error, createOut)
	}

	// The second exec reuses the container. It must not see the segment left
	// by the first exec.
	check, checkOut := execWithOutput(t, m,
		`wc -l < /proc/sysvipc/shm && test "$(wc -l < /proc/sysvipc/shm)" -eq 1`)
	if check.Status != runner.StatusNormal {
		t.Fatalf("ipc leaked to next exec: %v %v output=%q", check.Status, check.Error, checkOut)
	}
}
