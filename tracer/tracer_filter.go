package tracer

import libseccomp "github.com/seccomp/libseccomp-golang"

const (
	msgDisallow int16 = iota + 1
	msgHandle
)

func addFilterAction(filter *libseccomp.ScmpFilter, name string, action libseccomp.ScmpAction) error {
	syscallID, err := libseccomp.GetSyscallFromName(name)
	if err != nil {
		return err
	}
	err = filter.AddRule(syscallID, action)
	if err != nil {
		return err
	}
	return nil
}

func (r *Tracer) buildFilter() (*libseccomp.ScmpFilter, error) {
	// make filter
	var defaultAction libseccomp.ScmpAction
	// if debug, allow all syscalls and output what was blocked
	if r.Unsafe || r.ShowDetails {
		defaultAction = libseccomp.ActTrace.SetReturnCode(msgDisallow)
	} else {
		defaultAction = libseccomp.ActKill
	}
	filter, err := libseccomp.NewFilter(defaultAction)
	if err != nil {
		return nil, err
	}

	for _, s := range r.Allow {
		err := addFilterAction(filter, s, libseccomp.ActAllow)
		if err != nil {
			return nil, err
		}
	}

	for _, s := range r.Trace {
		err := addFilterAction(filter, s, libseccomp.ActTrace.SetReturnCode(msgHandle))
		if err != nil {
			return nil, err
		}
	}
	return filter, nil
}
