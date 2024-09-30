package main

import (
	"os"
	"strings"
	"syscall"

	"github.com/mattn/go-shellwords"
	"mvdan.cc/sh/v3/syntax"
)

var HOME string

func checkCmd(cmd string) bool {
	_, args, err := shellwords.ParseWithEnvs(cmd)
	if err != nil {
		return false
	}
	args[0] = strings.TrimPrefix(args[0], "/usr/bin/")
	switch args[0] {
	case
		"echo",
		"export",
		"exit",
		"x2goagent",
		"x2gobasepath",
		"x2gocmdexitmessage",
		"x2gofeature",
		"x2gofeaturelist",
		"x2gofm",
		"x2gogetapps",
		"x2gogetservers",
		"x2gokdrive",
		"x2gokdriveclient",
		"x2golistdesktops",
		"x2golistmounts",
		"x2golistsessions",
		"x2golistshadowsessions",
		"x2gomountdirs",
		"x2gooptionsstring",
		"x2gopath",
		"x2goprint",
		"x2goresume-session",
		"x2goruncommand",
		"x2goserver-run-extensions",
		"x2gosessionlimit",
		"x2gosetkeyboard",
		"x2gostartagent",
		"x2gosuspend-session",
		"x2goterminate-session",
		"x2goumount-session",
		"x2goversion":
		return true
	case "scp":
		path := ""
		for i := 1; i < len(args); i++ {
			if args[i] != "-t" && args[i] != "-r" {
				if path != "" {
					return false
				}
				path = args[i]
			}
		}
		if path == ".x2go/ssh" {
			path = HOME + "/" + path
			dirs, err := os.ReadDir(path)
			if err != nil {
				return true
			}
			return len(dirs) <= 0
		} else {
			if !strings.HasPrefix(path, ".x2go/") {
				return false
			}
			path = HOME + "/" + path
			dirs, err := os.ReadDir(path)
			if err != nil {
				return true
			}
			f := true
			for _, dir := range dirs {
				var maxSize = 0
				switch dir.Name() {
				case "cmdoutput":
					maxSize = 1000
				case "cmd.pid":
					maxSize = 20
				case "options":
					maxSize = 1000
				case "state":
					maxSize = 20
				case "sshd.pid":
					maxSize = 20
				case "session.log":
					file, err := os.OpenFile(path+"/"+dir.Name(), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0777)
					if err != nil {
						f = false
					}
					file.Close()
					maxSize = 1
				default:
					maxSize = 0
				}
				stat, err := os.Stat(path + "/" + dir.Name())
				if err != nil {
					f = false
				}
				size := stat.Size()
				if size > int64(maxSize) {
					f = false
				}
			}
			return f
		}
	case "setsid":
		return checkCmd(args[1])
	case "bash":
		var script = ""
		for i := 1; i < len(args); i++ {
			if args[i] != "-l" && args[i] != "-c" {
				if script != "" {
					return false
				}
				script = args[i]
			}
		}
		var f = true
		cmds := parseCmd(script)
		for _, cmd := range cmds {
			f = f && checkCmd(cmd)
		}
		return f
	default:
		return false
	}
}

func parseCmd(script string) []string {
	var cmds []string
	r := strings.NewReader(script)
	f, _ := syntax.NewParser().Parse(r, "")
	stmts := f.Stmts
	for _, stmt := range stmts {
		st, ed := stmt.Cmd.Pos().Col()-1, stmt.End().Col()-1
		cmds = append(cmds, script[st:ed])
	}
	return cmds
}

func main() {
	SSH_ORIGINAL_COMMAND := os.Getenv("SSH_ORIGINAL_COMMAND")
	HOME = os.Getenv("HOME")
	cmd := parseCmd(SSH_ORIGINAL_COMMAND)
	// Temporarily release ssh&&scp
	if SSH_ORIGINAL_COMMAND == "" {
		syscall.Exec("/bin/bash", []string{"bash", "-il"}, os.Environ())
		return
	}
	_, args, _ := shellwords.ParseWithEnvs(cmd[0])
	if args[0] == "/usr/lib/openssh/sftp-server" {
		syscall.Exec("/bin/bash", []string{"bash", "-c", SSH_ORIGINAL_COMMAND}, os.Environ())
		return
	}
	// Temporarily release ssh&&scp
	if len(cmd) == 1 && checkCmd(cmd[0]) {
		syscall.Exec("/bin/bash", []string{"bash", "-c", SSH_ORIGINAL_COMMAND}, os.Environ())
	}
}
