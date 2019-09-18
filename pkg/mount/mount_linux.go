package mount

import (
	"os"
	"syscall"
)

// Mount calls mount syscall
func (m *Mount) Mount() error {
	if err := os.MkdirAll(m.Target, 0755); err != nil {
		return err
	}
	if err := syscall.Mount(m.Source, m.Target, m.FsType, m.Flags, m.Data); err != nil {
		return err
	}
	// Read-only bind mount need to be remounted
	const bindRo = syscall.MS_BIND | syscall.MS_RDONLY
	if m.Flags&bindRo == bindRo {
		if err := syscall.Mount("", m.Target, m.FsType, m.Flags|syscall.MS_REMOUNT, m.Data); err != nil {
			return err
		}
	}
	return nil
}
