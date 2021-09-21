package mount

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	bind  = unix.MS_BIND | unix.MS_NOSUID | unix.MS_PRIVATE | unix.MS_REC
	mFlag = unix.MS_NOSUID | unix.MS_NOATIME | unix.MS_NODEV
)

// NewDefaultBuilder creates default builder for minimal rootfs
func NewDefaultBuilder() *Builder {
	return NewBuilder().
		WithBind("/usr", "usr", true).
		WithBind("/lib", "lib", true).
		WithBind("/lib64", "lib64", true).
		WithBind("/bin", "bin", true)
}

// Build creates sequence of syscalls for fork_exec
func (b *Builder) Build() ([]SyscallParams, error) {
	var err error
	ret := make([]SyscallParams, 0, len(b.Mounts))
	for _, m := range b.Mounts {
		var mknod bool
		if mknod, err = isBindMountFileOrNotExists(m); err != nil {
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

// FilterNotExist removes bind mount that does not exists
func (b *Builder) FilterNotExist() *Builder {
	rt := b.Mounts[:0]
	for _, m := range b.Mounts {
		if m.IsBindMount() {
			if _, err := os.Stat(m.Source); os.IsNotExist(err) {
				continue
			}
		}
		rt = append(rt, m)
	}
	b.Mounts = rt
	return b
}

func isBindMountFileOrNotExists(m Mount) (bool, error) {
	if m.IsBindMount() {
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

// WithProc add proc file system
func (b *Builder) WithProc() *Builder {
	b.Mounts = append(b.Mounts, Mount{
		Source: "proc",
		Target: "proc",
		FsType: "proc",
		Flags:  unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RDONLY,
	})
	return b
}

func (b Builder) String() string {
	var sb strings.Builder
	sb.WriteString("Mounts: ")
	for i, m := range b.Mounts {
		sb.WriteString(m.String())
		if i != len(b.Mounts)-1 {
			sb.WriteString(", ")
		}
	}
	return sb.String()
}
