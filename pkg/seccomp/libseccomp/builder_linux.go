package libseccomp

import (
	"syscall"

	"github.com/criyle/go-sandbox/pkg/seccomp"
	libseccomp "github.com/elastic/go-seccomp-bpf"
	"golang.org/x/net/bpf"
)

// Builder is used to build the filter
type Builder struct {
	Allow, Trace []string
	Default      Action
}

var actTrace = libseccomp.ActionTrace

// Build builds the filter
func (b *Builder) Build() (seccomp.Filter, error) {
	policy := libseccomp.Policy{
		DefaultAction: ToSeccompAction(b.Default),
		Syscalls: []libseccomp.SyscallGroup{
			{
				Action: libseccomp.ActionAllow,
				Names:  b.Allow,
			},
			{
				Action: actTrace,
				Names:  b.Trace,
			},
		},
	}
	program, err := policy.Assemble()
	if err != nil {
		return nil, err
	}
	return ExportBPF(program)
}

// ExportBPF convert libseccomp filter to kernel readable BPF content
func ExportBPF(filter []bpf.Instruction) (seccomp.Filter, error) {
	raw, err := bpf.Assemble(filter)
	if err != nil {
		return nil, err
	}
	return sockFilter(raw), nil
}

func sockFilter(raw []bpf.RawInstruction) []syscall.SockFilter {
	filter := make([]syscall.SockFilter, 0, len(raw))
	for _, instruction := range raw {
		filter = append(filter, syscall.SockFilter{
			Code: instruction.Op,
			Jt:   instruction.Jt,
			Jf:   instruction.Jf,
			K:    instruction.K,
		})
	}
	return filter
}
