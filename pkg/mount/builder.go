package mount

import (
	"os"

	"golang.org/x/sys/unix"
)

const (
	bind  = unix.MS_BIND | unix.MS_NOSUID | unix.MS_PRIVATE
	mFlag = unix.MS_NOSUID | unix.MS_NOATIME | unix.MS_NODEV
)

// Builder builds fork_exec friendly mount syscall format
type Builder struct {
	Mounts []Mount
}

// NewBuilder creates new mount builder instance
func NewBuilder() *Builder {
	return &Builder{}
}

// Build creates sequence of syscalls for fork_exec
// skipNotExists skips bind mounts that source not exists
func (b *Builder) Build(skipNotExists bool) ([]SyscallParams, error) {
	var err error
	ret := make([]SyscallParams, 0, len(b.Mounts))
	for _, m := range b.Mounts {
		mknod := false
		if mknod, err = isBindMountFileOrNotExists(m); err != nil {
			if skipNotExists {
				continue
			}
			return nil, err
		}
		sp, err := m.ToSyscall()
		if err != nil {
			return nil, err
		}
		sp.MakeNod = mknod
		ret = append(ret, *sp)
	}
	return ret, nil
}

func isBindMountFileOrNotExists(m Mount) (bool, error) {
	if m.Flags&unix.MS_BIND == unix.MS_BIND {
		if fi, err := os.Stat(m.Source); os.IsNotExist(err) {
			return false, err
		} else if !fi.IsDir() {
			return true, err
		}
	}
	return false, nil
}

// WithMounts add mounts to builder
func (b *Builder) WithMounts(m []Mount) *Builder {
	b.Mounts = append(b.Mounts, m...)
	return b
}

// WithMount add single mount to builder
func (b *Builder) WithMount(m Mount) *Builder {
	b.Mounts = append(b.Mounts, m)
	return b
}

// WithBind adds a bind mount to builder
func (b *Builder) WithBind(source, target string, readonly bool) *Builder {
	var flags uintptr = bind
	if readonly {
		flags |= unix.MS_RDONLY
	}
	b.Mounts = append(b.Mounts, Mount{
		Source: source,
		Target: target,
		Flags:  flags,
	})
	return b
}

// WithTmpfs add a tmpfs mount to builder
func (b *Builder) WithTmpfs(target, data string) *Builder {
	b.Mounts = append(b.Mounts, Mount{
		Source: "tmpfs",
		Target: target,
		FsType: "tmpfs",
		Flags:  mFlag,
		Data:   data,
	})
	return b
}