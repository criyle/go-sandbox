package memfd

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const roSeal = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE

// DupToMemfd convers a fd to sealed memfd for given name
func DupToMemfd(name string, fin *os.File) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("DupToMemfd: memfd_create failed(%v)", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("DupToMemfd: memfd new file failed")
	}
	// TODO: Send file might be more efficient here
	if _, err = io.Copy(file, fin); err != nil {
		file.Close()
		return nil, fmt.Errorf("DupToMemfd: memfd io copy failed(%v)", err)
	}
	// make memfd readonly
	if _, err = unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, roSeal); err != nil {
		file.Close()
		return nil, fmt.Errorf("DupToMemfd: memfd seal failed(%v)", err)
	}
	return file, nil
}
