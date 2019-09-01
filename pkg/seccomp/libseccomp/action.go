package libseccomp

import (
	"github.com/criyle/go-sandbox/pkg/seccomp"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

// ToSeccompAction convert action to libseccomp compatible action
func ToSeccompAction(a seccomp.Action) libseccomp.ScmpAction {
	var action libseccomp.ScmpAction
	switch a.Action() {
	case seccomp.ActionAllow:
		action = libseccomp.ActAllow
	case seccomp.ActionErrno:
		action = libseccomp.ActErrno
	case seccomp.ActionTrace:
		action = libseccomp.ActTrace
	default:
		action = libseccomp.ActKill
	}
	action = action.SetReturnCode(a.ReturnCode())
	return action
}
