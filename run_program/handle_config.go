package main

import (
	"os"

	tracer "github.com/criyle/go-judger/tracer"
)

func inifConf(t *tracer.Tracer, fs *fileSets, sc *syscallCounter, pType string, addRead []string, addWrite []string, allowProc bool) {
	for _, name := range defaultReadableFileNameList {
		fs.Readable.Add(name)
	}

	if t.WorkPath == "" {
		t.WorkPath, _ = os.Getwd()
	}
	fs.Statable.Add(t.WorkPath)

	if pType != "java7" && pType != "java8" {
		fs.addFilePermission(t.Args[0], filePermRead)
	} else {
		// ...
		fs.addFilePermission(t.Args[0], filePermRead)
	}
	fs.addFilePermission(t.WorkPath, filePermRead)

	for _, name := range addRead {
		fs.addFilePermission(name, filePermRead)
	}

	for _, name := range addWrite {
		fs.addFilePermission(name, filePermWrite)
	}

	fs.Writable.Add("/dev/null")

	if allowProc {
		t.Allow = append(t.Allow, "clone", "fork", "vfork", "nanosleep", "execve")
	}

	var (
		writeableFiles, readableFiles, statableFiles, softbanFiles []string
	)

	switch pType {
	case "python2.7":
		sc.add("set_tid_address", 1)
		sc.add("set_robust_list", 1)
		t.Allow = append(t.Allow, "futex", "getdents", "getdents64", "prlimit64", "getpid", "sysinfo")

		readableFiles = append(readableFiles,
			"/usr/bin/python2.7",
			"/usr/lib/python2.7/",
			"/usr/bin/lib/python2.7/",
			"/usr/local/lib/python2.7/",
			"/usr/lib/pymodules/python2.7/",
			"/usr/bin/Modules/",
			"/usr/bin/pybuilddir.txt",
			"/usr/lib/locale/",
			t.WorkPath+"/answer.code",
		)

		statableFiles = append(statableFiles, "/usr", "/usr/bin")
		t.Args = append([]string{"/usr/bin/python2.7", "-E", "-s", "-B"}, t.Args...)

	case "python3":
		sc.add("set_tid_address", 1)
		sc.add("set_robust_list", 1)
		t.Allow = append(t.Allow, "futex", "getdents", "getdents64", "prlimit64", "getpid", "sysinfo", "getrandom")

		readableFiles = append(readableFiles,
			"/usr/bin/python3",
			"/usr/lib/python3/",
			"/usr/bin/python3.6",
			"/usr/lib/python3.6/",
			"/usr/bin/lib/python3.6/",
			"/usr/local/lib/python3.6/",
			"/usr/bin/pyvenv.cfg",
			"/usr/pyvenv.cfg",
			"/usr/bin/Modules",
			"/usr/bin/pybuilddir.txt",
			"/usr/lib/dist-python",
			"/usr/lib/locale/",
			t.WorkPath+"/answer.code",
		)

		statableFiles = append(statableFiles, "/usr", "/usr/bin", "/usr/lib", "/usr/lib/python36.zip")
		t.Args = append([]string{"/usr/bin/python3", "-I", "-B"}, t.Args...)

	case "java7":
	case "java8":
		// ....

	case "compiler":
		t.Allow = append(t.Allow, "gettid", "set_tid_address", "set_robust_list", "futex",
			"getpid", "vfork", "fork", "clone", "execve", "wait4",
			"clock_gettime", "clock_getres",
			"setrlimit", "pipe",
			"getdents64", "getdents",
			"umask", "rename", "chmod", "mkdir",
			"chdir", "fchdir",
			"ftruncate",
			"sched_getaffinity", "sched_yield",
			"uname", "sysinfo",
			"prlimit64", "getrandom",
		)
		// soft ban
		t.Trace = append(t.Trace, "socket", "connect", "geteuid", "getuid")

		writeableFiles = append(writeableFiles, "/tmp/", t.WorkPath+"/")
		readableFiles = append(readableFiles,
			t.WorkPath,
			absPath(0, t.WorkPath+"/../runtime")+"/",
			"/etc/oracle/java/usagetracker.properties",
			"/usr/",
			"/lib/",
			"/lib64/",
			"/bin/",
			"/sbin/",
			"/sys/devices/system/cpu/",
			"/proc/",
			"/etc/timezone",
			"/etc/fpc-2.6.2.cfg.d/",
			"/etc/fpc.cfg",
			"/*",
		)
		fs.Readable.SystemRoot = true

		softbanFiles = append(softbanFiles,
			"/etc/nsswitch.conf",
			"/etc/passwd",
		)
	}

	for _, name := range writeableFiles {
		fs.Writable.Add(name)
	}

	for _, name := range readableFiles {
		fs.Readable.Add(name)
	}

	for _, name := range statableFiles {
		fs.Statable.Add(name)
	}

	for _, name := range softbanFiles {
		fs.SoftBan.Add(name)
	}
}
