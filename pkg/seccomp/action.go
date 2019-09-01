package seccomp

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

// MsgDisallow, Msghandle defines the action needed when traped by
// seccomp filter
const (
	MsgDisallow int16 = iota + 1
	MsgHandle
)

// WithReturnCode set the return code when action is trace or ban
func (a Action) WithReturnCode(code int16) Action {
	return a.Action() | Action(code)<<16
}

// ReturnCode get the return code
func (a Action) ReturnCode() int16 {
	return int16(a >> 16)
}

// Action get the basic action
func (a Action) Action() Action {
	return Action(a & 0xffff)
}
