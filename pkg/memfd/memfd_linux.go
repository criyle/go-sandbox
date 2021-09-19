package memfd

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const createFlag = unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING
const roSeal = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE

// New creates a new memfd, caller need to close the file
func New(name string) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, createFlag)
	if err != nil {
		return nil, fmt.Errorf("memfd: memfd_create failed %v", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("memfd: NewFile failed for %v", name)
	}
	return file, nil
}

// DupToMemfd reads content from reader to sealed (readonly) memfd for given name
func DupToMemfd(name string, reader io.Reader) (*os.File, error) {
	file, err := New(name)
	if err != nil {
		return nil, fmt.Errorf("DupToMemfd: %v", err)
	}
	// linux syscall sendfile might be more efficient here if reader is a file
	if _, err = file.ReadFrom(reader); err != nil {
		file.Close()
		return nil, fmt.Errorf("DupToMemfd: read from %v", err)
	}
	// make memfd readonly
	if _, err = unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, roSeal); err != nil {
		file.Close()
		return nil, fmt.Errorf("DupToMemfd: memfd seal %v", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		return nil, fmt.Errorf("DupToMemfd: file seek %v", err)
	}
	return file, nil
}
