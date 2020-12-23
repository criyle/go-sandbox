package libseccomp

import (
	libseccomp "github.com/elastic/go-seccomp-bpf"
)

// ToSeccompAction convert action to libseccomp compatible action
func ToSeccompAction(a Action) libseccomp.Action {
	var action libseccomp.Action
	switch a.Action() {
	case ActionAllow:
		action = libseccomp.ActionAllow
	case ActionErrno:
		action = libseccomp.ActionErrno
	case ActionTrace:
		action = libseccomp.ActionTrace
	default:
		action = libseccomp.ActionKillProcess
	}
	// the least 16 bit of ret value is SECCOMP_RET_DATA
	// although it might not officially supported by go-seccomp-bpf
	// action = action.WithReturnData(int(a.ReturnCode()))
	return action
}
