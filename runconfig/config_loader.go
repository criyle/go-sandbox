package runconfig

// GetConf return file access check set, syscall counter, allow and traced syscall arrays and new args
func GetConf(pType, workPath string, args, addRead, addWrite []string, allowProc, showDetails bool) *Handler {
	var (
		fs    = NewFileSets()
		sc    = NewSyscallCounter()
		allow = append([]string{}, defaultSyscallAllows...)
		trace = append([]string{}, defaultSyscallTraces...)
	)

	fs.Readable.AddRange(defaultReadableFiles, workPath)
	fs.Writable.AddRange(defaultWritableFiles, workPath)
	fs.AddFilePermission(args[0], FilePermRead)
	fs.AddFilePermission(workPath, FilePermRead)

	fs.Readable.AddRange(addRead, workPath)
	fs.Writable.AddRange(addWrite, workPath)

	if c, o := runprogramConfig[pType]; o {
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

	return &Handler{
		SyscallAllow:   allow,
		SyscallTrace:   trace,
		Args:           args,
		FileSet:        fs,
		SyscallCounter: sc,
		ShowDetails:    showDetails,
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
