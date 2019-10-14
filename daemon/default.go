package daemon

import (
	"github.com/criyle/go-sandbox/pkg/mount"
	"golang.org/x/sys/unix"
)

const (
	roBind = unix.MS_BIND | unix.MS_NOSUID | unix.MS_PRIVATE | unix.MS_RDONLY
	mFlag  = unix.MS_NOSUID | unix.MS_NOATIME | unix.MS_NODEV
)

// default parameters. I was tend to reuse the configs but it is hard since there are some
// cross device symbolic
var (
	DefaultPath = "PATH=/usr/local/bin:/usr/bin:/bin"

	// rootfs created by bind mounting
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
