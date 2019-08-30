package unshare

import (
	"os"

	"golang.org/x/sys/unix"

	"github.com/criyle/go-sandbox/pkg/mount"
)

// AddBind is the additional bind mounts besides the default one
type AddBind struct {
	Source, Target string
	ReadOnly       bool
}

const (
	bind2        = unix.MS_BIND | unix.MS_NOSUID | unix.MS_NOATIME | unix.MS_NODEV | unix.MS_NODIRATIME
	bind         = unix.MS_BIND | unix.MS_NOSUID | unix.MS_PRIVATE
	roBind       = bind | unix.MS_RDONLY
	noExecRoBind = roBind | unix.MS_NOEXEC
	remountRo    = unix.MS_REMOUNT | unix.MS_RDONLY
)

// default parameters. I was tend to reuse the configs but it is hard since there are some
// cross device symblics
var (
	DefaultMounts = []*mount.Mount{
		{
			Source: "/usr/lib/locale",
			Target: "usr/lib/locale",
			Flags:  roBind,
		},
		{
			Source: "/usr",
			Target: "usr",
			Flags:  roBind,
		},
		{
			Source: "/lib",
			Target: "lib",
			Flags:  roBind,
		},
		{
			Source: "/lib64",
			Target: "lib64",
			Flags:  roBind,
		},
		{
			Source: "/bin",
			Target: "bin",
			Flags:  roBind,
		},
	}
)

// GetDefaultMounts returns default mount parameters for given root
func GetDefaultMounts(root string, add []AddBind) []*mount.Mount {
	mounts := make([]*mount.Mount, 0, len(DefaultMounts)+len(add))
	// check if bind mount source exists, e.g. /lib64 does not exists on arm
	for _, m := range DefaultMounts {
		if _, err := os.Stat(m.Source); !os.IsNotExist(err) {
			mounts = append(mounts, m)
		}
	}
	for _, m := range add {
		flags := bind
		if m.ReadOnly {
			flags = roBind
		}
		mounts = append(mounts, &mount.Mount{
			Source: m.Source,
			Target: m.Target,
			Flags:  uintptr(flags),
		})
	}
	return mounts
}
