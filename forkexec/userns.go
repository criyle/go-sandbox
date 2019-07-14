package forkexec

import (
	"strconv"

	"golang.org/x/sys/unix"
)

// writeUidGidMappings writes User ID and Group ID mappings for user namespaces
// for a process and it is called from the parent process.
func writeIDMaps(pid int) error {
	pidStr := strconv.Itoa(pid)
	uidStr := strconv.Itoa(unix.Geteuid())
	gidStr := strconv.Itoa(unix.Getegid())
	if err := writeFile("/proc/"+pidStr+"/uid_map", []byte("0 "+uidStr+" 1")); err != nil {
		return err
	}
	if err := writeFile("/proc/"+pidStr+"/setgroups", []byte("deny")); err != nil {
		return err
	}
	if err := writeFile("/proc/"+pidStr+"/gid_map", []byte("0 "+gidStr+" 1")); err != nil {
		return err
	}
	return nil
}

// writeFile writes file
func writeFile(path string, content []byte) error {
	fd, err := unix.Open(path, unix.O_RDWR, 0)
	if err != nil {
		return err
	}
	if _, err := unix.Write(fd, content); err != nil {
		unix.Close(fd)
		return err
	}
	if err := unix.Close(fd); err != nil {
		return err
	}
	return nil
}
