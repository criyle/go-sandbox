package tracee

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
	filter.Release()
	if err != nil {
		return nil, err
	}

	// directly convert pointer
	return &syscall.SockFprog{
		Len:    uint16(len(bin) / 8),
		Filter: (*syscall.SockFilter)(unsafe.Pointer(&bin[0])),
	}, nil
}
