package main

import (
	"flag"
	"fmt"
	"os"
)

const (
	pathEnv = "PATH=/usr/local/bin:/usr/bin:/bin"
)

func printUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <args>\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(2)
}
