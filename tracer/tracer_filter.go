package tracer

import libseccomp "github.com/seccomp/libseccomp-golang"

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
	//filter, err := libseccomp.NewFilter(libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	var defaultAction libseccomp.ScmpAction
	if r.Debug {
		defaultAction = libseccomp.ActTrace.SetReturnCode(100)
	} else {
		defaultAction = libseccomp.ActKill
	}
	filter, err := libseccomp.NewFilter(defaultAction)
	if err != nil {
		return nil, err
	}

	for _, s := range r.Allow {
		err := addFilterAction(filter, s, libseccomp.ActAllow)
		//log.Println("[+] allow syscall: ", s)
		if err != nil {
			return nil, err
		}
	}

	for _, s := range r.Trace {
		err := addFilterAction(filter, s, libseccomp.ActTrace.SetReturnCode(10))
		//log.Println("[+] trace syscall: ", s)
		if err != nil {
			return nil, err
		}
	}
	return filter, nil
}
