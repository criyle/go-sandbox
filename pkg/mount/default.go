package mount

import "golang.org/x/sys/unix"

// RoBind is read-only bind mount flags
const (
	RoBind = unix.MS_BIND | unix.MS_NOSUID | unix.MS_PRIVATE | unix.MS_RDONLY
)

var (
	// DefaultMounts is a example of minimal rootfs
	DefaultMounts = []Mount{
		{
			Source: "/usr",
			Target: "usr",
			Flags:  RoBind,
		},
		{
			Source: "/lib",
			Target: "lib",
			Flags:  RoBind,
		},
		{
			Source: "/lib64",
			Target: "lib64",
			Flags:  RoBind,
		},
		{
			Source: "/bin",
			Target: "bin",
			Flags:  RoBind,
		},
	}
)
