package libseccomp

import (
	"github.com/criyle/go-sandbox/pkg/seccomp"
	libseccomp "github.com/elastic/go-seccomp-bpf"
)

// ToSeccompAction convert action to libseccomp compatible action
func ToSeccompAction(a seccomp.Action) libseccomp.Action {
	var action libseccomp.Action
	switch a.Action() {
	case seccomp.ActionAllow:
		action = libseccomp.ActionAllow
	case seccomp.ActionErrno:
		action = libseccomp.ActionErrno
	case seccomp.ActionTrace:
		action = libseccomp.ActionTrace
	default:
		action = libseccomp.ActionKillProcess
	}
	// the least 16 bit of ret value is SECCOMP_RET_DATA
	// although it might not officially supported by go-seccomp-bpf
	action = action.WithReturnData(int(a.ReturnCode()))
	return action
}
