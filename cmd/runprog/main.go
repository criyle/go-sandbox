package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/criyle/go-sandbox/runner"
)

const (
	pathEnv = "PATH=/usr/local/bin:/usr/bin:/bin"
)

func printUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <args>\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(2)
}

// Status defines uoj/run_program constants
type Status int

// UOJ run_program constants
const (
	StatusNormal  Status = iota // 0
	StatusInvalid               // 1
	StatusRE                    // 2
	StatusMLE                   // 3
	StatusTLE                   // 4
	StatusOLE                   // 5
	StatusBan                   // 6
	StatusFatal                 // 7
)

func getStatus(s runner.Status) int {
	switch s {
	case runner.StatusNormal:
		return int(StatusNormal)
	case runner.StatusInvalid:
		return int(StatusInvalid)
	case runner.StatusTimeLimitExceeded:
		return int(StatusTLE)
	case runner.StatusMemoryLimitExceeded:
		return int(StatusMLE)
	case runner.StatusOutputLimitExceeded:
		return int(StatusOLE)
	case runner.StatusDisallowedSyscall:
		return int(StatusBan)
	case runner.StatusSignalled, runner.StatusNonzeroExitStatus:
		return int(StatusRE)
	default:
		return int(StatusFatal)
	}
}

func debug(v ...interface{}) {
	if showDetails {
		fmt.Fprintln(os.Stderr, v...)
	}
}
