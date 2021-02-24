package forkexec

import (
	"os"
	"testing"
)

func TestWrite(t *testing.T) {
	c, err := os.ReadFile("test.sb")
	if err != nil {
		t.Error(err)
		return
	}

	// before load profile, it is ok
	f, err := os.OpenFile("/tmp/sandbox_test", os.O_CREATE|os.O_RDWR, 0777)
	if err != nil {
		t.Error(err)
		return
	}
	f.Close()

	if err = SandboxLoadProfile(string(c)); err != nil {
		t.Error(err)
		return
	}

	// after is not ok
	f, err = os.OpenFile("/tmp/sandbox_test", os.O_CREATE|os.O_RDWR, 0777)
	if !os.IsPermission(err) {
		t.Error(err)
		return
	}
	f.Close()
}
