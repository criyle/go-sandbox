package daemon

import (
	"os"
	"path"
	"syscall"
)

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

func closeOnExecFds(s []int) {
	for _, f := range s {
		syscall.CloseOnExec(f)
	}
}

func closeFds(s []int) {
	for _, f := range s {
		syscall.Close(f)
	}
}

// removeContents delete content of a directory
func removeContents(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()

	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}

	for _, name := range names {
		err = os.RemoveAll(path.Join(dir, name))
		if err != nil {
			return err
		}
	}
	return nil
}
