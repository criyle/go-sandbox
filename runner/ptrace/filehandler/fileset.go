package filehandler

import (
	"path/filepath"
	"strings"
)

// FileSet stores the file permissions in the hierarchical set
type FileSet struct {
	Set        map[string]bool
	SystemRoot bool
}

// FilePerm stores the permission apply to the file
type FilePerm int

// FilePermWrite / Read / Stat are permissions
const (
	FilePermWrite = iota + 1
	FilePermRead
	FilePermStat
)

// NewFileSet creates the new file set
func NewFileSet() FileSet {
	return FileSet{make(map[string]bool), false}
}

// IsInSetSmart same from uoj-judger
func (s *FileSet) IsInSetSmart(name string) bool {
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
		name = dirname(name)
	}
	if level == 1 && s.Set["/*"] {
		return true
	}
	if s.Set["/"] {
		return true
	}
	return false
}

// Add adds a single file path into the FileSet
func (s *FileSet) Add(name string) {
	if name == "/" {
		s.SystemRoot = true
	} else {
		s.Set[name] = true
	}
}

// AddRange adds multiple files into the FileSet
// If path is relative path, add according to the workPath
func (s *FileSet) AddRange(names []string, workPath string) {
	for _, n := range names {
		if filepath.IsAbs(n) {
			if n == "/" {
				s.SystemRoot = true
			} else {
				s.Set[n] = true
			}
		} else {
			s.Set[filepath.Join(workPath, n)+"/"] = true
		}
	}
}

// FileSets agregates multiple permissions including write / read / stat / soft ban
type FileSets struct {
	Writable, Readable, Statable, SoftBan FileSet
}

// NewFileSets creates new FileSets struct
func NewFileSets() *FileSets {
	return &FileSets{NewFileSet(), NewFileSet(), NewFileSet(), NewFileSet()}
}

// IsWritableFile determines whether the file path inside the write set
func (s *FileSets) IsWritableFile(name string) bool {
	return s.Writable.IsInSetSmart(name) || s.Writable.IsInSetSmart(realPath(name))
}

// IsReadableFile determines whether the file path inside the read / write set
func (s *FileSets) IsReadableFile(name string) bool {
	return s.IsWritableFile(name) || s.Readable.IsInSetSmart(name) || s.Readable.IsInSetSmart(realPath(name))
}

// IsStatableFile determines whether the file path inside the stat / read / write set
func (s *FileSets) IsStatableFile(name string) bool {
	return s.IsReadableFile(name) || s.Statable.IsInSetSmart(name) || s.Statable.IsInSetSmart(realPath(name))
}

// IsSoftBanFile determines whether the file path inside the softban set
func (s *FileSets) IsSoftBanFile(name string) bool {
	return s.SoftBan.IsInSetSmart(name) || s.SoftBan.IsInSetSmart(realPath(name))
}

// AddFilePermission adds the file into fileSets according to the given permission
func (s *FileSets) AddFilePermission(name string, mode FilePerm) {
	if mode == FilePermWrite {
		s.Writable.Add(name)
	} else if mode == FilePermRead {
		s.Readable.Add(name)
	} else if mode == FilePermStat {
		s.Statable.Add(name)
	}
	for name = dirname(name); name != ""; name = dirname(name) {
		s.Statable.Add(name)
	}
}

// GetExtraSet evaluates the concated file set according to real path or raw path
func GetExtraSet(extra, raw []string) []string {
	rt := make([]string, 0, len(extra)+len(raw))
	rt = append(rt, raw...)
	for _, v := range extra {
		rt = append(rt, realPath(v))
	}
	return rt
}

// basename return path with last "/"
func basename(path string) string {
	if p := strings.LastIndex(path, "/"); p >= 0 {
		return path[:p+1]
	}
	return path
}

// dirname return path without last "/"
func dirname(path string) string {
	if p := strings.LastIndex(path, "/"); p >= 0 {
		return path[:p]
	}
	return ""
}

func realPath(p string) string {
	f, err := filepath.EvalSymlinks(p)
	if err != nil {
		return ""
	}
	return f
}
