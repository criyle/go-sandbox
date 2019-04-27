package secutil

import (
	"testing"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func TestBuildFilter(t *testing.T) {
	defaultAction := libseccomp.ActKill
	filter, err := buildFilterMock(defaultAction)
	if err != nil {
		t.Error("BuildFilter failed")
	}
	if d, e := filter.GetDefaultAction(); e != nil || d != defaultAction {
		t.Error("DefaultAction does not match by BuildFilter")
	}
}

func TestFilterToBPF(t *testing.T) {
	defaultAction := libseccomp.ActKill
	filter, err := buildFilterMock(defaultAction)
	if err != nil {
		t.Error("BuildFilter failed")
	}
	prog, err := FilterToBPF(filter)
	if err != nil || prog == nil || prog.Filter == nil {
		t.Error("BuildFilter failed")
	}
}

func TestBuildFilterFail(t *testing.T) {
	defaultAction := libseccomp.ActKill
	defaultTrace := libseccomp.ActTrace
	allow := []string{"fork"}
	trace := []string{"execve"}

	allowf := append(allow, "fail")
	filter, err := BuildFilter(defaultAction, defaultTrace, allowf, trace)
	if err == nil || filter != nil {
		t.Error("BuildFilter did not detect failure")
	}

	tracef := append(trace, "fail")
	filter, err = BuildFilter(defaultAction, defaultTrace, allow, tracef)
	if err == nil || filter != nil {
		t.Error("BuildFilter did not detect failure")
	}

	filter, err = BuildFilter(libseccomp.ActInvalid, defaultTrace, allow, trace)
	if err == nil || filter != nil {
		t.Error("BuildFilter did not detect failure")
	}
}

func TestAddActionFail(t *testing.T) {
	defaultAction := libseccomp.ActKill
	filter, _ := libseccomp.NewFilter(defaultAction)
	arch, _ := libseccomp.GetNativeArch()
	filter.RemoveArch(arch)
	err := addFilterAction(filter, "fork", defaultAction)
	if err == nil {
		t.Error("addFilterAction did not detect failure")
	}
}

func buildFilterMock(d libseccomp.ScmpAction) (*libseccomp.ScmpFilter, error) {
	defaultTrace := libseccomp.ActTrace
	allow := []string{"fork"}
	trace := []string{"execve"}
	return BuildFilter(d, defaultTrace, allow, trace)
}
