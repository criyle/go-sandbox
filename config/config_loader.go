package config

import "github.com/criyle/go-sandbox/runner/ptrace/filehandler"

// GetConf return file access check set, syscall counter, allow and traced syscall arrays and new args
func GetConf(pType, workPath string, args, addRead, addWrite []string,
	allowProc bool) ([]string, []string, []string, *filehandler.Handler) {
	var (
		fs    = filehandler.NewFileSets()
		sc    = filehandler.NewSyscallCounter()
		allow = append(append([]string{}, defaultSyscallAllows...), archSyscallAllows...)
		trace = append(append([]string{}, defaultSyscallTraces...), archSyscallTraces...)
	)

	fs.Readable.AddRange(defaultReadableFiles, workPath)
	fs.Readable.AddRange(archReadableFiles, workPath)
	fs.Writable.AddRange(defaultWritableFiles, workPath)
	fs.AddFilePermission(args[0], filehandler.FilePermRead)
	fs.AddFilePermission(workPath, filehandler.FilePermRead)

	fs.Readable.AddRange(addRead, workPath)
	fs.Writable.AddRange(addWrite, workPath)

	if c, o := runptraceConfig[pType]; o {
		allow = append(allow, c.Syscall.ExtraAllow...)
		trace = append(trace, c.Syscall.ExtraBan...)
		sc.AddRange(c.Syscall.ExtraCount)
		fs.Readable.AddRange(c.FileAccess.ExtraRead, workPath)
		fs.Writable.AddRange(c.FileAccess.ExtraWrite, workPath)
		fs.Statable.AddRange(c.FileAccess.ExtraStat, workPath)
		fs.SoftBan.AddRange(c.FileAccess.ExtraBan, workPath)
		args = append(c.RunCommand, args...)
	}
	if allowProc {
		allow = append(allow, defaultProcSyscalls...)
	}
	allow, trace = cleanTrace(allow, trace)

	return args, allow, trace, &filehandler.Handler{
		FileSet:        fs,
		SyscallCounter: sc,
	}
}

func keySetToSlice(m map[string]bool) []string {
	rt := make([]string, 0, len(m))
	for k := range m {
		rt = append(rt, k)
	}
	return rt
}

func cleanTrace(allow, trace []string) ([]string, []string) {
	// make sure allow, trace no duplicate
	traceMap := make(map[string]bool)
	for _, s := range trace {
		traceMap[s] = true
	}
	allowMap := make(map[string]bool)
	for _, s := range allow {
		if !traceMap[s] {
			allowMap[s] = true
		}
	}
	return keySetToSlice(allowMap), keySetToSlice(traceMap)
}
