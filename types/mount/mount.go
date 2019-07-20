package mount

import (
	"os"
	"syscall"
)

// Mount defines syscall for mount points
type Mount struct {
	Source, Target, FsType, Data string
	Flags                        uintptr
}

// SyscallParams defines the raw syscall arguments to mount
type SyscallParams struct {
	Source, Target, FsType, Data *byte
	Flags                        uintptr
}

// ToSyscall convert Mount to SyscallPrams
func (m *Mount) ToSyscall() (*SyscallParams, error) {
	var data *byte
	source, err := syscall.BytePtrFromString(m.Source)
	if err != nil {
		return nil, err
	}
	target, err := syscall.BytePtrFromString(m.Target)
	if err != nil {
		return nil, err
	}
	fsType, err := syscall.BytePtrFromString(m.FsType)
	if err != nil {
		return nil, err
	}
	if m.Data != "" {
		data, err = syscall.BytePtrFromString(m.Data)
		if err != nil {
			return nil, err
		}
	}
	return &SyscallParams{
		Source: source,
		Target: target,
		FsType: fsType,
		Flags:  m.Flags,
		Data:   data,
	}, nil
}

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

// ToSyscalls converts arrays of Mounts into SyscallParams
func ToSyscalls(ms []*Mount) ([]*SyscallParams, error) {
	ret := make([]*SyscallParams, 0, len(ms))
	for _, m := range ms {
		sp, err := m.ToSyscall()
		if err != nil {
			return nil, err
		}
		ret = append(ret, sp)
	}
	return ret, nil
}

// Mounts calls multiple mount syscalls
func Mounts(ms []*Mount) error {
	for _, m := range ms {
		err := m.Mount()
		if err != nil {
			return err
		}
	}
	return nil
}
