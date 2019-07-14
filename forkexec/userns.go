package forkexec

import (
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	fileOption = unix.O_RDWR
	filePerm   = 0755
)

var (
	uidMap    = [...]byte{'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 'u', 'i', 'd', '_', 'm', 'a', 'p', 0}
	gidMap    = [...]byte{'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 'g', 'i', 'd', '_', 'm', 'a', 'p', 0}
	setGroups = [...]byte{'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 's', 'e', 't', 'g', 'r', 'o', 'u', 'p', 's', 0}
)

type fileWriteSyscall struct {
	fileName    *byte
	fileContent []byte
}

func prepareIDMap(userNs bool) []fileWriteSyscall {
	ret := make([]fileWriteSyscall, 0, 3)
	if userNs {
		ret = append(ret, fileWriteSyscall{
			fileName:    &uidMap[0],
			fileContent: []byte("0 " + strconv.Itoa(unix.Geteuid()) + " 1"),
		})
		ret = append(ret, fileWriteSyscall{
			fileName:    &gidMap[0],
			fileContent: []byte("0 " + strconv.Itoa(unix.Getegid()) + " 1"),
		})
		ret = append(ret, fileWriteSyscall{
			fileName:    &setGroups[0],
			fileContent: []byte("deny"),
		})
	}
	return ret
}
