package container

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"syscall"
	"testing"

	"github.com/criyle/go-sandbox/runner"
)

func init() {
	Init()
}

func BenchmarkContainer(b *testing.B) {
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		b.Error(err)
	}
	builder := &Builder{
		Root: tmpDir,
	}
	m, err := builder.Build()
	if err != nil {
		b.Error(err)
	}
	b.Cleanup(func() {
		m.Destroy()
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rt := m.Execve(context.TODO(), ExecveParam{
			Args: []string{"/bin/echo"},
			Env:  []string{"PATH=/bin"},
		})
		r := <-rt
		if r.Status != runner.StatusNormal {
			b.Error(r.Status, r.Error)
		}
	}
}

func TestContainerSuccess(t *testing.T) {
	t.Parallel()
	m := getEnv(t, nil)
	rt := m.Execve(context.TODO(), ExecveParam{
		Args: []string{"/bin/echo"},
		Env:  []string{"PATH=/bin"},
	})
	r := <-rt
	if r.Status != runner.StatusNormal {
		t.Error(r.Status, r.Error)
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
	rt := m.Execve(context.TODO(), ExecveParam{
		Args: []string{"/bin/echo"},
		Env:  []string{"PATH=/bin"},
	})
	r := <-rt
	if r.Status != runner.StatusNormal {
		t.Error(r.Status, r.Error)
	}
}

func TestContainerNotExists(t *testing.T) {
	t.Parallel()
	m := getEnv(t, nil)
	rt := m.Execve(context.TODO(), ExecveParam{
		Args: []string{"not_exists"},
		Env:  []string{"PATH=/bin"},
	})
	r := <-rt
	if r.Status != runner.StatusRunnerError {
		t.Error(r.Status, r.Error)
	}
}

func TestContainerSyncFuncFail(t *testing.T) {
	t.Parallel()
	m := getEnv(t, nil)
	err := errors.New("test error")
	rt := m.Execve(context.TODO(), ExecveParam{
		Args: []string{"/bin/echo"},
		Env:  []string{"PATH=/bin"},
		SyncFunc: func(pid int) error {
			return err
		},
	})
	r := <-rt
	if r.Status != runner.StatusRunnerError {
		t.Error(r.Status, r.Error)
	}
}

func getEnv(t *testing.T, credGen CredGenerator) Environment {
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Error(err)
	}
	builder := &Builder{
		Root:          tmpDir,
		CredGenerator: credGen,
	}
	m, err := builder.Build()
	if err != nil {
		t.Error(err)
	}
	return m
}
