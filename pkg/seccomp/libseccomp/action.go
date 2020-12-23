package libseccomp

// Action is seccomp trap action
type Action uint32

// Action defines seccomp action to the syscall
// default value 0 is invalid
const (
	ActionAllow Action = iota + 1
	ActionErrno
	ActionTrace
	ActionKill
)

// MsgDisallow, Msghandle defines the action needed when trapped by
// seccomp filter
const (
	MsgDisallow int16 = iota + 1
	MsgHandle
)

// Action get the basic action
func (a Action) Action() Action {
	return Action(a & 0xffff)
}
