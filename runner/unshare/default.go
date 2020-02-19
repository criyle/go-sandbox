// +build linux

package unshare

import (
	"golang.org/x/sys/unix"

	"github.com/criyle/go-sandbox/pkg/mount"
)

const roBind = unix.MS_BIND | unix.MS_NOSUID | unix.MS_PRIVATE | unix.MS_RDONLY

var (
	// DefaultMounts is a example of minimal rootfs
	DefaultMounts = []mount.Mount{
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
