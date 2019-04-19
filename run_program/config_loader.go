package main

// getConf return file access check set, syscall counter, allow and traced syscall arrays and new args
func getConf(pType, workPath string, args, addRead, addWrite []string, allowProc bool) (*fileSets, syscallCounter, []string, []string, []string) {
	var (
		fs    = newFileSets()
		sc    = newSyscallCounter()
		allow = append([]string{}, defaultSyscallAllows...)
		trace = append([]string{}, defaultSyscallTraces...)
	)

	fs.Readable.AddRange(defaultReadableFiles)
	fs.Writable.AddRange(defaultWritableFiles)
	fs.addFilePermission(args[0], filePermRead)
	fs.addFilePermission(workPath, filePermRead)

	fs.Readable.AddRange(addRead)
	fs.Writable.AddRange(addWrite)

	if c, o := runprogramConfig[pType]; o {
		allow = append(allow, c.Syscall.ExtraAllow...)
		trace = append(trace, c.Syscall.ExtraBan...)
		sc.addRange(c.Syscall.ExtraCount)
		fs.Readable.AddRange(c.FileAccess.ExtraRead)
		fs.Writable.AddRange(c.FileAccess.ExtraWrite)
		fs.Statable.AddRange(c.FileAccess.ExtraStat)
		fs.SoftBan.AddRange(c.FileAccess.ExtraBan)
		args = append(c.RunCommand, args...)
	}
	if allowProc {
		allow = append(allow, defaultProcSyscalls...)
	}
	allow, trace = cleanTrace(allow, trace)

	return fs, sc, allow, trace, args
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
