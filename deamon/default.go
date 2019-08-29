package deamon

import (
	"os"

	"github.com/criyle/go-sandbox/pkg/mount"
	"golang.org/x/sys/unix"
)

const (
	bind   = unix.MS_BIND | unix.MS_NOSUID | unix.MS_PRIVATE
	roBind = bind | unix.MS_RDONLY
	mFlag  = unix.MS_NOSUID | unix.MS_NOATIME | unix.MS_NODEV
)

// default parameters. I was tend to reuse the configs but it is hard since there are some
// cross device symblics
var (
	DefaultPath = "PATH=/usr/local/bin:/usr/bin:/bin"

	// rootfs created by bind mounting
	DefaultMounts = []*mount.Mount{
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
		// work dir at /w
		{
			Source: "tmpfs",
			Target: "w",
			FsType: "tmpfs",
			Flags:  mFlag,
		},
		// tmpfs at /tmp
		{
			Source: "tmpfs",
			Target: "tmp",
			FsType: "tmpfs",
			Flags:  mFlag,
		},
	}
)

func init() {
	// check if bind mount source exists, e.g. /lib64 does not exists on arm
	mounts := make([]*mount.Mount, 0, len(DefaultMounts))
	for _, m := range DefaultMounts {
		if m.Source != "tmpfs" {
			if _, err := os.Stat(m.Source); !os.IsNotExist(err) {
				mounts = append(mounts, m)
			}
		} else {
			mounts = append(mounts, m)
		}
	}
	DefaultMounts = mounts
}
