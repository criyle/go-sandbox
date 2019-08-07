package deamon

func intSliceToUintptr(s []int) []uintptr {
	var r []uintptr
	if len(s) > 0 {
		r = make([]uintptr, len(s))
		for i, x := range s {
			r[i] = uintptr(x)
		}
	}
	return r
}

func uintptrSliceToInt(s []uintptr) []int {
	var r []int
	if len(s) > 0 {
		r = make([]int, len(s))
		for i, x := range s {
			r[i] = int(x)
		}
	}
	return r
}
