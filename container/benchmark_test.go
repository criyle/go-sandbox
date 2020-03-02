package container

import (
	"context"
	"errors"
	"io/ioutil"
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
		return
	}
	builder := &Builder{
		Root: tmpDir,
	}
	m, err := builder.Build()
	if err != nil {
		b.Error(err)
		return
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
			return
		}
	}
}

func TestContainerSuccess(t *testing.T) {
	m := getEnv(t)
	if m == nil {
		return
	}
	rt := m.Execve(context.TODO(), ExecveParam{
		Args: []string{"/bin/echo"},
		Env:  []string{"PATH=/bin"},
	})
	r := <-rt
	if r.Status != runner.StatusNormal {
		t.Error(r.Status, r.Error)
		return
	}
}

func TestContainerNotExists(t *testing.T) {
	m := getEnv(t)
	if m == nil {
		return
	}
	rt := m.Execve(context.TODO(), ExecveParam{
		Args: []string{"not_exists"},
		Env:  []string{"PATH=/bin"},
	})
	r := <-rt
	if r.Status != runner.StatusRunnerError {
		t.Error(r.Status, r.Error)
		return
	}
}

func TestContainerSyncFuncFail(t *testing.T) {
	m := getEnv(t)
	if m == nil {
		return
	}
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
		return
	}
}

func getEnv(t *testing.T) Environment {
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Error(err)
		return nil
	}
	builder := &Builder{
		Root: tmpDir,
	}
	m, err := builder.Build()
	if err != nil {
		t.Error(err)
		return nil
	}
	return m
}
