package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/coreos/go-systemd/v22/journal"
	"github.com/mattn/go-shellwords"
	"mvdan.cc/sh/v3/syntax"
)

var home string

func checkCmd(cmd string) bool {
	_, args, err := shellwords.ParseWithEnvs(cmd)
	if err != nil {
		return false
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		return true
	}
	path, err = filepath.Abs(path)
	if err != nil {
		log.Printf("Parse path error: %v\n", err)
		return false
	}
	switch path {
	case
		"/usr/bin/echo",
		"/usr/bin/x2goagent",
		"/usr/bin/x2gobasepath",
		"/usr/bin/x2gocmdexitmessage",
		"/usr/bin/x2gofeature",
		"/usr/bin/x2gofeaturelist",
		"/usr/bin/x2gofm",
		"/usr/bin/x2gogetapps",
		"/usr/bin/x2gogetservers",
		"/usr/bin/x2gokdrive",
		"/usr/bin/x2gokdriveclient",
		"/usr/bin/x2golistdesktops",
		"/usr/bin/x2golistmounts",
		"/usr/bin/x2golistsessions",
		"/usr/bin/x2golistshadowsessions",
		"/usr/bin/x2gomountdirs",
		"/usr/bin/x2gooptionsstring",
		"/usr/bin/x2gopath",
		"/usr/bin/x2goprint",
		"/usr/bin/x2goresume-session",
		"/usr/bin/x2goruncommand",
		"/usr/bin/x2goserver-run-extensions",
		"/usr/bin/x2gosessionlimit",
		"/usr/bin/x2gosetkeyboard",
		"/usr/bin/x2gostartagent",
		"/usr/bin/x2gosuspend-session",
		"/usr/bin/x2goterminate-session",
		"/usr/bin/x2goumount-session",
		"/usr/bin/x2goversion":
		return true
	case "/usr/bin/scp":
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
			path = home + "/" + path
			dirs, err := os.ReadDir(path)
			if err != nil {
				return true
			}
			if len(dirs) >= 10 {
				return false
			}
			f := true
			for _, dir := range dirs {
				var maxSize int
				if dir.IsDir() || (dir.Type()&os.ModeSymlink) != 0 {
					return false
				}
				fileName := dir.Name()
				if !strings.HasPrefix(fileName, "key.") {
					return false
				}
				if strings.HasSuffix(fileName, ".ident") {
					maxSize = 1000
				} else {
					maxSize = 4000
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
		} else {
			if !strings.HasPrefix(path, ".x2go/") {
				return false
			}
			path = home + "/" + path
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
				case ".pulse-client.conf":
					maxSize = 1000
				case ".pulse-cookie":
					maxSize = 1000
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
	case "/usr/bin/setsid":
		return checkCmd(args[1])
	case "/usr/bin/bash":
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

func setSelfPriority(priority int) {
	pid := os.Getpid()
	cmd := exec.Command("sudo", "renice", "-n", strconv.Itoa(priority), "-p", strconv.Itoa(pid))
	cmd.Run()
}

func main() {
	setSelfPriority(-20)
	sshOriginalCmd := os.Getenv("SSH_ORIGINAL_COMMAND")
	home = os.Getenv("HOME")
	cmd := parseCmd(sshOriginalCmd)
	// Temporarily release ssh&&scp
	if sshOriginalCmd == "" {
		syscall.Exec("/bin/bash", []string{"bash", "-il"}, os.Environ())
		return
	}
	_, args, _ := shellwords.ParseWithEnvs(cmd[0])
	if args[0] == "/usr/lib/openssh/sftp-server" {
		syscall.Exec("/bin/bash", []string{"bash", "-c", sshOriginalCmd}, os.Environ())
		return
	}
	// Temporarily release ssh&&scp
	if len(cmd) == 1 && checkCmd(cmd[0]) {
		syscall.Exec("/bin/bash", []string{"bash", "-c", sshOriginalCmd}, os.Environ())
	} else {
		journal.Print(journal.PriNotice, "Reject cmd: %v\n", sshOriginalCmd)
	}
}
