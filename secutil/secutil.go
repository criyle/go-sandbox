// Package secutil provides utility functions to manipulate seccomp filters
// provided by libseccomp
package secutil

import (
	"io/ioutil"
	"os"
	"syscall"
	"unsafe"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

// FilterToBPF convert libseccomp filter to kernel readable BPF style
func FilterToBPF(filter *libseccomp.ScmpFilter) (*syscall.SockFprog, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	// export to pipe
	go func() {
		filter.ExportBPF(w)
		w.Close()
	}()

	// get BPF binary
	bin, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// directly convert pointer
	return &syscall.SockFprog{
		Len:    uint16(len(bin) / 8),
		Filter: (*syscall.SockFilter)(unsafe.Pointer(&bin[0])),
	}, nil
}

// BuildFilter builds libseccomp filter by defining the default action, trace action
// allow and trace syscall names
func BuildFilter(defaultAct, traceAct libseccomp.ScmpAction, allow, trace []string) (*libseccomp.ScmpFilter, error) {
	filter, err := libseccomp.NewFilter(defaultAct)
	if err != nil {
		return nil, err
	}

	for _, s := range allow {
		err := addFilterAction(filter, s, libseccomp.ActAllow)
		if err != nil {
			return nil, err
		}
	}

	for _, s := range trace {
		err := addFilterAction(filter, s, traceAct)
		if err != nil {
			return nil, err
		}
	}
	return filter, nil
}

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
