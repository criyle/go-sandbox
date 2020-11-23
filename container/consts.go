package container

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

	initArg = "container_init"

	containerUID = 1000
	containerGID = 1000

	containerName = "go-sandbox"
	containerWD   = "/w"

	containerMaxProc = 1
)
