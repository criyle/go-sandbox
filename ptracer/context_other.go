// +build !linux

package ptracer

// Context empty structure filler for other OS
type Context struct {
	Pid int
}

func (c *Context) SyscallNo() uint {
	return 0
}

func (c *Context) Arg0() uint {
	return 0
}

func (c *Context) Arg1() uint {
	return 0
}

func (c *Context) Arg2() uint {
	return 0
}

func (c *Context) Arg3() uint {
	return 0
}

func (c *Context) Arg4() uint {
	return 0
}

func (c *Context) Arg5() uint {
	return 0
}

func (c *Context) SetReturnValue(retval int) {

}

func (c *Context) GetString(addr uintptr) string {
	return ""
}
