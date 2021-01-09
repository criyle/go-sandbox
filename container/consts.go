package container

type cmdType int

const (
	cmdPing cmdType = iota + 1
	cmdCopyIn
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
