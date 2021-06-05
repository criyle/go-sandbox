package container

import (
	"context"
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/criyle/go-sandbox/runner"
)

func init() {
	Init()
}

func BenchmarkContainer(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		b.Error(err)
	}
	builder := &Builder{
		Root:   tmpDir,
		Stderr: os.Stderr,
	}
	n := runtime.GOMAXPROCS(0)
	ch := make(chan Environment, n)
	for i := 0; i < n; i++ {
		m, err := builder.Build()
		if err != nil {
			b.Error(err)
		}
		b.Cleanup(func() {
			m.Destroy()
		})
		ch <- m
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		m := <-ch
		for pb.Next() {
			r := m.Execve(context.TODO(), ExecveParam{
				Args: []string{"/bin/true"},
				Env:  []string{"PATH=/bin"},
			})
			if r.Status != runner.StatusNormal {
				b.Error(r.Status, r.Error)
			}
		}
	})
}

func TestContainerSuccess(t *testing.T) {
	t.Parallel()
	m := getEnv(t, nil)
	r := m.Execve(context.TODO(), ExecveParam{
		Args: []string{"/bin/true"},
		Env:  []string{"PATH=/bin"},
	})
	if r.Status != runner.StatusNormal {
		t.Fatal(r.Status, r.Error, r)
	}
}

type credgen struct{}

func (c credgen) Get() syscall.Credential {
	return syscall.Credential{
		Uid: 10000,
		Gid: 10000,
	}
}

func TestContainerSetCred(t *testing.T) {
	t.Parallel()
	if os.Getpid() != 1 {
		t.Skip("root required for this test")
	}
	m := getEnv(t, credgen{})
	r := m.Execve(context.TODO(), ExecveParam{
		Args: []string{"/bin/true"},
		Env:  []string{"PATH=/bin"},
	})
	if r.Status != runner.StatusNormal {
		t.Fatal(r.Status, r.Error)
	}
}

func TestContainerNotExists(t *testing.T) {
	t.Parallel()
	m := getEnv(t, nil)
	r := m.Execve(context.TODO(), ExecveParam{
		Args: []string{"not_exists"},
		Env:  []string{"PATH=/bin"},
	})
	if r.Status != runner.StatusRunnerError {
		t.Fatal(r.Status, r.Error)
	}
}

func TestContainerSyncFuncFail(t *testing.T) {
	t.Parallel()
	m := getEnv(t, nil)
	err := errors.New("test error")
	r := m.Execve(context.TODO(), ExecveParam{
		Args: []string{"/bin/true"},
		Env:  []string{"PATH=/bin"},
		SyncFunc: func(pid int) error {
			return err
		},
	})
	if r.Status != runner.StatusRunnerError {
		t.Fatal(r.Status, r.Error)
	}
}

func getEnv(t *testing.T, credGen CredGenerator) Environment {
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Remove(tmpDir)
	})
	builder := &Builder{
		Root:          tmpDir,
		CredGenerator: credGen,
		Stderr:        os.Stderr,
	}
	m, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.Destroy()
	})
	return m
}
