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

type testCase struct {
	name     string
	param    ExecveParam
	expected runner.Status
}

var err error = errors.New("test error")

var successParam = ExecveParam{
	Args: []string{"/bin/true"},
	Env:  []string{"PATH=/bin"},
}

var tests []testCase = []testCase{
	{
		name:     "Success",
		param:    successParam,
		expected: runner.StatusNormal,
	},
	{
		name: "SuccessWithSync",
		param: ExecveParam{
			Args:     []string{"/bin/true"},
			Env:      []string{"PATH=/bin"},
			SyncFunc: func(p int) error { return nil },
		},
		expected: runner.StatusNormal,
	},
	{
		name: "NotExists",
		param: ExecveParam{
			Args: []string{"not_exists"},
			Env:  []string{"PATH=/bin"},
		},
		expected: runner.StatusRunnerError,
	},
	{
		name: "NotExistsWithSync",
		param: ExecveParam{
			Args:     []string{"not_exists"},
			Env:      []string{"PATH=/bin"},
			SyncFunc: func(p int) error { return nil },
		},
		expected: runner.StatusRunnerError,
	},
	{
		name: "SyncFuncFail",
		param: ExecveParam{
			Args: []string{"/bin/true"},
			Env:  []string{"PATH=/bin"},
			SyncFunc: func(pid int) error {
				return err
			},
		},
		expected: runner.StatusRunnerError,
	},
	{
		name: "SyncFuncFailAfterExec",
		param: ExecveParam{
			Args: []string{"/bin/true"},
			Env:  []string{"PATH=/bin"},
			SyncFunc: func(pid int) error {
				return err
			},
			SyncAfterExec: true,
		},
		expected: runner.StatusRunnerError,
	},
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
	runTest(t, successParam, runner.StatusNormal, credgen{})
}

func runTest(t *testing.T, param ExecveParam, expected runner.Status, credGen CredGenerator) {
	t.Parallel()
	m := getEnv(t, credGen)
	r := m.Execve(context.TODO(), param)
	if r.Status != expected {
		t.Fatal(r.Status, r.Error, r)
	}
	if err := m.Ping(); err != nil {
		t.Fatal(err)
	}
	// can also success once more (no protocol mismatch)
	r = m.Execve(context.TODO(), successParam)
	if r.Status != runner.StatusNormal {
		t.Fatal(r.Status, r.Error, r)
	}
}

func TestCases(t *testing.T) {
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			runTest(t, c.param, c.expected, nil)
		})
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
