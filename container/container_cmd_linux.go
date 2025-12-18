package container

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/criyle/go-sandbox/pkg/unixsocket"
)

func (c *containerServer) handlePing() error {
	return c.sendReply(reply{}, unixsocket.Msg{})
}

func (c *containerServer) handleConf(conf *confCmd) error {
	if conf != nil {
		c.containerConfig = conf.Conf
		if err := initContainer(conf.Conf); err != nil {
			return err
		}
		if c.ContainerUID == 0 {
			c.ContainerUID = containerUID
		}
		if c.ContainerGID == 0 {
			c.ContainerGID = containerGID
		}
		env, err := readDotEnv()
		if err != nil {
			return err
		}
		c.defaultEnv = env
	}
	return c.sendReply(reply{}, unixsocket.Msg{})
}

func (c *containerServer) handleOpen(open []OpenCmd) error {
	if len(open) == 0 {
		return c.sendErrorReply("open: no open parameter received")
	}

	// open files
	fds := make([]int, 0, len(open))
	fileToClose := make([]*os.File, 0, len(open)) // let sendMsg close these files
	openErrors := make([]string, len(open))
	for i, o := range open {
		if o.MkdirAll {
			dir := filepath.Dir(o.Path)
			if err := os.MkdirAll(dir, 0777); err != nil {
				openErrors[i] = "mkdir: " + err.Error()
				continue
			}
		}

		outFile, err := os.OpenFile(o.Path, o.Flag, o.Perm)
		if err != nil {
			openErrors[i] = err.Error()
			continue
		}
		fileToClose = append(fileToClose, outFile)
		fds = append(fds, int(outFile.Fd()))
	}

	return c.sendReplyFiles(reply{OpenErrors: openErrors}, unixsocket.Msg{Fds: fds}, fileToClose)
}

func (c *containerServer) handleSymlink(links []SymbolicLink) error {
	if len(links) == 0 {
		return c.sendErrorReply("symlink: no parameters received")
	}

	symlinkErrors := make([]string, len(links))
	for i, l := range links {
		if err := os.Symlink(l.Target, l.LinkPath); err != nil {
			symlinkErrors[i] = err.Error()
			continue
		}
	}

	return c.sendReply(reply{OpenErrors: symlinkErrors}, unixsocket.Msg{})
}

func (c *containerServer) handleDelete(delete *deleteCmd) error {
	if delete == nil {
		return c.sendErrorReply("delete: no parameter provided")
	}
	if err := os.Remove(delete.Path); err != nil {
		return c.sendErrorReply("delete: %v", err)
	}
	return c.sendReply(reply{}, unixsocket.Msg{})
}

func (c *containerServer) handleReset() error {
	for _, m := range c.Mounts {
		if !m.IsTmpFs() {
			continue
		}
		if err := removeContents(filepath.Join("/", m.Target)); err != nil {
			return c.sendErrorReply("reset: %v %v", m.Target, err)
		}
	}
	return c.sendReply(reply{}, unixsocket.Msg{})
}

// readDotEnv attempts to read /.env file and save as default environment variables
func readDotEnv() ([]string, error) {
	f, err := os.Open("/.env")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("dotenv: open /.env: %w", err)
	}
	defer f.Close()

	var ret []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "=") {
			return nil, fmt.Errorf("dotenv: invalid line: %s", line)
		}
		ret = append(ret, line)
	}
	return ret, nil
}
