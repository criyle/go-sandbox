package libseccomp

import (
	"io/ioutil"
	"os"

	"github.com/criyle/go-sandbox/pkg/seccomp"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

// Builder is used to build the filter
type Builder struct {
	Allow, Trace []string
	Default      seccomp.Action
}

var actTrace = libseccomp.ActTrace.SetReturnCode(seccomp.MsgHandle)

// Build builds the filter
func (b *Builder) Build() (seccomp.Filter, error) {
	filter, err := libseccomp.NewFilter(ToSeccompAction(b.Default))
	if err != nil {
		return nil, err
	}
	defer filter.Release()

	if err = addFilterActions(filter, b.Allow, libseccomp.ActAllow); err != nil {
		return nil, err
	}
	if err = addFilterActions(filter, b.Trace, actTrace); err != nil {
		return nil, err
	}
	return ExportBPF(filter)
}

// ExportBPF convert libseccomp filter to kernel readable BPF content
func ExportBPF(filter *libseccomp.ScmpFilter) (seccomp.Filter, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	// export BPF to pipe
	go func() {
		filter.ExportBPF(w)
		w.Close()
	}()

	// get BPF binary
	bin, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return seccomp.Filter(bin), nil
}

func addFilterActions(filter *libseccomp.ScmpFilter, names []string, action libseccomp.ScmpAction) error {
	for _, s := range names {
		if err := addFilterAction(filter, s, action); err != nil {
			return err
		}
	}
	return nil
}

func addFilterAction(filter *libseccomp.ScmpFilter, name string, action libseccomp.ScmpAction) error {
	syscallID, err := libseccomp.GetSyscallFromName(name)
	if err != nil {
		return err
	}
	if err = filter.AddRule(syscallID, action); err != nil {
		return err
	}
	return nil
}
