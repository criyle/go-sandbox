// +build linux

package forkexec

import (
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// writeUidGidMappings writes User ID and Group ID mappings for user namespaces
// for a process and it is called from the parent process.
func writeIDMaps(r *Runner, pid int) error {
	var uidMappings, gidMappings, setGroups []byte
	pidStr := strconv.Itoa(pid)

	if r.UIDMappings == nil {
		uidMappings = []byte("0 " + strconv.Itoa(unix.Geteuid()) + " 1")
	} else {
		uidMappings = formatIDMappings(r.UIDMappings)
	}
	if err := writeFile("/proc/"+pidStr+"/uid_map", uidMappings); err != nil {
		return err
	}

	if r.GIDMappings == nil || !r.GIDMappingsEnableSetgroups {
		setGroups = setGIDDeny
	} else {
		setGroups = setGIDAllow
	}
	if err := writeFile("/proc/"+pidStr+"/setgroups", setGroups); err != nil {
		return err
	}

	if r.GIDMappings == nil {
		gidMappings = []byte("0 " + strconv.Itoa(unix.Getegid()) + " 1")
	} else {
		gidMappings = formatIDMappings(r.GIDMappings)
	}
	if err := writeFile("/proc/"+pidStr+"/gid_map", gidMappings); err != nil {
		return err
	}
	return nil
}

func formatIDMappings(idMap []syscall.SysProcIDMap) []byte {
	var data []byte
	for _, im := range idMap {
		data = append(data, []byte(strconv.Itoa(im.ContainerID)+" "+strconv.Itoa(im.HostID)+" "+strconv.Itoa(im.Size)+"\n")...)
	}
	return data
}

// writeFile writes file
func writeFile(path string, content []byte) error {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
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
