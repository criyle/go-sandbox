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
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := syscall.Mount(m.Source, m.Target, m.FsType, m.Flags, m.Data); err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	// Read-only bind mount need to be remounted
	const bindRo = syscall.MS_BIND | syscall.MS_RDONLY
	const mask = syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_NOATIME | syscall.MS_NODIRATIME | syscall.MS_RELATIME
	if m.Flags&bindRo == bindRo {
		// Ensure the flag retains for bind mount
		var s syscall.Statfs_t
		if err := syscall.Statfs(m.Source, &s); err != nil {
			return fmt.Errorf("statfs: %w", err)
		}
		flag := m.Flags | syscall.MS_REMOUNT | uintptr(s.Flags&mask)
		if err := syscall.Mount("", m.Target, m.FsType, flag, m.Data); err != nil {
			return fmt.Errorf("remount: %w", err)
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

// IsTmpFs returns if the fsType is tmpfs
func (m Mount) IsTmpFs() bool {
	return m.FsType == "tmpfs"
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
			// double check if file exists
			f, err1 := os.Lstat(target)
			if err1 == nil && f.Mode().IsRegular() {
				return nil
			}
			return err
		}
	}
	return nil
}

func (m Mount) String() string {
	flag := "rw"
	if m.Flags&syscall.MS_RDONLY == syscall.MS_RDONLY {
		flag = "ro"
	}
	switch {
	case m.Flags&syscall.MS_BIND == syscall.MS_BIND:
		return fmt.Sprintf("bind[%s:%s:%s]", m.Source, m.Target, flag)

	case m.FsType == "tmpfs":
		return fmt.Sprintf("tmpfs[%s]", m.Target)

	case m.FsType == "proc":
		return fmt.Sprintf("proc[%s]", flag)

	default:
		return fmt.Sprintf("mount[%s,%s:%s:%x,%s]", m.FsType, m.Source, m.Target, m.Flags, m.Data)
	}
}
