package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// basename return path with last "/"
func basename(path *string) string {
	if p := strings.LastIndex(*path, "/"); p >= 0 {
		return (*path)[:p+1]
	}
	return *path
}

// dirname return path without last "/"
func dirname(path *string) string {
	if p := strings.LastIndex(*path, "/"); p >= 0 {
		return (*path)[:p]
	}
	return ""
}

// getProcCwd gets the process CWD
func getProcCwd(pid int) string {
	fileName := "/proc/self/cwd"
	if pid > 0 {
		fileName = fmt.Sprintf("/proc/%d/cwd", pid)
	}
	s, err := os.Readlink(fileName)
	if err != nil {
		return ""
	}
	return s
}

// absPath calculates the absolute path for a process
// built-in function did the dirty works to resolve relative paths
func absPath(pid int, p string) string {
	// if relative path
	if path.IsAbs(p) {
		return path.Join(getProcCwd(pid), p)
	}
	return path.Clean(p)
}

func realPath(p string) string {
	f, err := filepath.EvalSymlinks(p)
	if err != nil {
		return f
	}
	return ""
}

// fileSet stores the file permissions
type fileSet struct {
	Set        map[string]bool
	SystemRoot bool
}

type filePerm int

const (
	filePermWrite = iota + 1
	filePermRead
	filePermStat
)

func newFileSet() fileSet {
	return fileSet{make(map[string]bool), false}
}

// IsInSetSmart same from uoj-judger
func (s *fileSet) IsInSetSmart(name string) bool {
	if s.Set[name] {
		return true
	}
	if name == "/" && s.SystemRoot {
		return true
	}
	// check ...
	level := 0
	for level = 0; name != ""; level++ {
		if level == 1 && s.Set[name+"/*"] {
			return true
		}
		if s.Set[name+"/"] {
			return true
		}
		name = dirname(&name)
	}
	if level == 1 && s.Set["/*"] {
		return true
	}
	if s.Set["/"] {
		return true
	}
	return false
}

func (s *fileSet) Add(name string) {
	s.Set[name] = true
}

type fileSets struct {
	Writable, Readable, Statable, SoftBan fileSet
}

func newFileSets() fileSets {
	return fileSets{newFileSet(), newFileSet(), newFileSet(), newFileSet()}
}

func (s *fileSets) isWritableFile(name *string) bool {
	return s.Writable.IsInSetSmart(*name) || s.Writable.IsInSetSmart(realPath(*name))
}

func (s *fileSets) isReadableFile(name *string) bool {
	return s.isWritableFile(name) || s.Readable.IsInSetSmart(*name) || s.Readable.IsInSetSmart(realPath(*name))
}

func (s *fileSets) isStatableFile(name *string) bool {
	return s.isReadableFile(name) || s.Statable.IsInSetSmart(*name) || s.Statable.IsInSetSmart(realPath(*name))
}

func (s *fileSets) isSoftBanFile(name *string) bool {
	return s.SoftBan.IsInSetSmart(*name) || s.SoftBan.IsInSetSmart(realPath(*name))
}

func (s *fileSets) addFilePermission(name string, mode filePerm) {
	if mode == filePermWrite {
		s.Writable.Add(name)
	} else if mode == filePermRead {
		s.Readable.Add(name)
	} else if mode == filePermStat {
		s.Statable.Add(name)
	}
	for name = dirname(&name); name != ""; name = dirname(&name) {
		s.Statable.Add(name)
	}
}

var defaultReadableFileNameList = []string{
	"/etc/ld.so.nohwcap",
	"/etc/ld.so.preload",
	"/etc/ld.so.cache",
	"/lib/x86_64-linux-gnu/",
	"/usr/lib/x86_64-linux-gnu/",
	"/usr/lib/locale/locale-archive",
	"/proc/self/exe",
	"/etc/timezone",
	"/usr/share/zoneinfo/",
	"/dev/random",
	"/dev/urandom",
	"/proc/meminfo",
	"/etc/localtime",
}

type syscallCounter map[string]int

func newSyscallCounter() syscallCounter {
	return syscallCounter(make(map[string]int))
}

func (s *syscallCounter) add(name string, count int) {
	(*s)[name] = count
}

// check return inside, allow
func (s *syscallCounter) check(name string) (bool, bool) {
	n, o := (*s)[name]
	if o {
		(*s)[name] = n - 1
		if n <= 1 {
			return true, false
		}
		return true, true
	}
	return false, true
}
