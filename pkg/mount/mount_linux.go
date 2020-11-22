package mount

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Mount calls mount syscall
func (m *Mount) Mount() error {
	if err := ensureMountTargetExists(m.Source, m.Target); err != nil {
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

// IsBindMount returns if it is a bind mount
func (m Mount) IsBindMount() bool {
	return m.Flags&syscall.MS_BIND == syscall.MS_BIND
}

// IsReadOnly returns if it is a readonly mount
func (m Mount) IsReadOnly() bool {
	return m.Flags&syscall.MS_RDONLY == syscall.MS_RDONLY
}

func ensureMountTargetExists(source, target string) error {
	isFile := false
	if fi, err := os.Stat(source); err == nil {
		isFile = !fi.IsDir()
	}
	dir := target
	if isFile {
		dir = filepath.Dir(target)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if isFile {
		if err := syscall.Mknod(target, 0755, 0); err != nil {
			return err
		}
	}
	return nil
}

func (m Mount) String() string {
	switch {
	case m.Flags&syscall.MS_BIND == syscall.MS_BIND:
		flag := "rw"
		if m.Flags&syscall.MS_RDONLY == syscall.MS_RDONLY {
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
