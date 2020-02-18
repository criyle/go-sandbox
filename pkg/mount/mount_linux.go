package mount

import (
	"fmt"
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

func (m Mount) String() string {
	switch {
	case m.Flags|syscall.MS_BIND == syscall.MS_BIND:
		flag := "rw"
		if m.Flags|syscall.MS_RDONLY == syscall.MS_RDONLY {
			flag = "ro"
		}
		return fmt.Sprintf("bind[%s:%s:%s]", m.Source, m.Target, flag)

	case m.FsType == "tmpfs":
		return fmt.Sprintf("tmpfs[%s]", m.Target)

	case m.FsType == "proc":
		return fmt.Sprintf("proc[]")

	default:
		return fmt.Sprintf("mount[%s,%s:%s:%x,%s]", m.FsType, m.Source, m.Target, m.Flags, m.Data)
	}
}
