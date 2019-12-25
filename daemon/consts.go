package daemon

const (
	cmdPing   = "ping"
	cmdCopyIn = "copyin"
	cmdOpen   = "open"
	cmdDelete = "delete"
	cmdReset  = "reset"
	cmdExecve = "execve"
	cmdOk     = "ok"
	cmdKill   = "kill"
	cmdConf   = "conf"

	initArg = "init"

	currentExec = "/proc/self/exe"

	containerUID = 1000
	containerGID = 1000

	containerName = "daemon"
	containerWD   = "/w"

	containerMaxProc = 1
)
