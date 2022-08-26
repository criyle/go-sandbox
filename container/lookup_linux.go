package container

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var (
	errNotFound = errors.New("executable file not found in $PATH")
	errNoPath   = errors.New("no PATH environment variable provided for look up")
)

func findExecutable(file string) error {
	d, err := os.Stat(file)
	if err != nil {
		return err
	}
	if m := d.Mode(); !m.IsDir() && m&0111 != 0 {
		return nil
	}
	return fs.ErrPermission
}

func lookPath(name string, env []string) (string, error) {
	// don't look if abs path provided
	if filepath.Base(name) != name {
		return name, nil
	}

	// don't look if exist in current dir
	if err := findExecutable(name); err == nil {
		return name, nil
	}

	path, err := findPath(env)
	if err != nil {
		return "", err
	}
	for _, dir := range path {
		if dir == "" {
			dir = "."
		}
		p := filepath.Join(dir, name)
		if err := findExecutable(p); err == nil {
			return p, nil
		}
	}
	return "", errNotFound
}

func findPath(env []string) ([]string, error) {
	// find PATH=
	const pathPrefix = "PATH="
	for i := len(env) - 1; i >= 0; i-- {
		s := env[i]
		if strings.HasPrefix(s, pathPrefix) {
			return filepath.SplitList(s[len(pathPrefix):]), nil
		}
	}
	return nil, errNoPath
}
