package container

type cmdType int8

const (
	cmdPing cmdType = iota + 1
	cmdOpen
	cmdDelete
	cmdReset
	cmdExecve
	cmdOk
	cmdKill
	cmdConf

	initArg = "container_init"

	containerUID = 1000
	containerGID = 1000

	containerName = "go-sandbox"
	containerWD   = "/w"

	containerMaxProc = 1
)

var defaultSymLinks = []SymbolicLink{
	{LinkPath: "/dev/fd", Target: "/proc/self/fd"},
	{LinkPath: "/dev/stdin", Target: "/proc/self/fd/0"},
	{LinkPath: "/dev/stdout", Target: "/proc/self/fd/1"},
	{LinkPath: "/dev/stderr", Target: "/proc/self/fd/2"},
}

var defaultMaskPaths = []string{
	// https://github.com/containerd/containerd/blob/f0a32c66dad1e9de716c9960af806105d691cd78/oci/spec.go#L165-L176
	"/proc/acpi",
	"/proc/asound",
	"/proc/kcore",
	"/proc/keys",
	"/proc/latency_stats",
	"/proc/timer_list",
	"/proc/timer_stats",
	"/proc/sched_debug",
	"/sys/firmware",
	"/proc/scsi",

	"/usr/lib/wsl",
}
