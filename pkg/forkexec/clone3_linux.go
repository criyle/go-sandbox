package forkexec

// cloneArgs holds arguments for clone3 Linux syscall.
// from src/syscall/exec_linux.go:196
type cloneArgs struct {
	flags      uint64 // Flags bit mask
	pidFD      uint64 // Where to store PID file descriptor (int *)
	childTID   uint64 // Where to store child TID, in child's memory (pid_t *)
	parentTID  uint64 // Where to store child TID, in parent's memory (pid_t *)
	exitSignal uint64 // Signal to deliver to parent on child termination
	stack      uint64 // Pointer to lowest byte of stack
	stackSize  uint64 // Size of stack
	tls        uint64 // Location of new TLS
	setTID     uint64 // Pointer to a pid_t array (since Linux 5.5)
	setTIDSize uint64 // Number of elements in set_tid (since Linux 5.5)
	cgroup     uint64 // File descriptor for target cgroup of child (since Linux 5.7)
}
