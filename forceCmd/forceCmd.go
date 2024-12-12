package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/coreos/go-systemd/v22/journal"
	"github.com/mattn/go-shellwords"
	"mvdan.cc/sh/v3/syntax"
)

var (
	home   string
	cpuNum int
)

func checkCmd(cmd string) (cmdList []string, allow bool) {
	allow = true
	_, args, err := shellwords.ParseWithEnvs(cmd)
	if err != nil {
		allow = false
		return
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		allow = true
		return
	}
	path, err = filepath.Abs(path)
	if err != nil {
		log.Printf("Parse path error: %v\n", err)
		allow = false
		return
	}
	cmdList = append(cmdList, path)
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
		"/usr/bin/x2golistsessions",
		"/usr/bin/x2golistshadowsessions",
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
		"/usr/bin/x2goversion":
		allow = true
		return
	case "/usr/bin/scp":
		path := ""
		for i := 1; i < len(args); i++ {
			if args[i] != "-t" && args[i] != "-r" {
				if path != "" {
					allow = false
					return
				}
				path = args[i]
			}
		}
		if path == ".x2go/ssh" {
			path = home + "/" + path
			dirs, err := os.ReadDir(path)
			if err != nil {
				allow = true
				return
			}
			if len(dirs) >= 10 {
				allow = false
				return
			}
			for _, dir := range dirs {
				var maxSize int
				if dir.IsDir() || (dir.Type()&os.ModeSymlink) != 0 {
					allow = false
					return
				}
				fileName := dir.Name()
				if !strings.HasPrefix(fileName, "key.") {
					allow = false
					return
				}
				if strings.HasSuffix(fileName, ".ident") {
					maxSize = 5000
				} else {
					maxSize = 10000
				}
				stat, err := os.Stat(path + "/" + dir.Name())
				if err != nil {
					allow = false
					return
				}
				size := stat.Size()
				if size > int64(maxSize) {
					allow = false
					return
				}
			}
			allow = true
			return
		} else {
			if !strings.HasPrefix(path, ".x2go/") {
				allow = false
				return
			}
			path = home + "/" + path
			dirs, err := os.ReadDir(path)
			if err != nil {
				allow = true
				return
			}
			for _, dir := range dirs {
				var maxSize = 0
				switch dir.Name() {
				case "cmdoutput":
					maxSize = 4000
				case "cmd.pid":
					maxSize = 20
				case "options":
					maxSize = 4000
				case "state":
					maxSize = 20
				case "sshd.pid":
					maxSize = 20
				case "session.log":
					file, err := os.OpenFile(path+"/"+dir.Name(), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0777)
					if err != nil {
						allow = false
						return
					}
					file.Close()
					maxSize = 1
				case ".pulse-client.conf":
					maxSize = 4000
				case ".pulse-cookie":
					maxSize = 4000
				default:
					maxSize = 0
				}
				stat, err := os.Stat(path + "/" + dir.Name())
				if err != nil {
					allow = false
					return
				}
				size := stat.Size()
				if size > int64(maxSize) {
					allow = false
					return
				}
			}
			allow = true
			return
		}
	case "/usr/bin/setsid":
		return checkCmd(args[1])
	case "/usr/bin/bash":
		var script = ""
		for i := 1; i < len(args); i++ {
			if args[i] != "-l" && args[i] != "-c" {
				if script != "" {
					allow = false
					return
				}
				script = args[i]
			}
		}
		allow = true
		cmds := parseCmd(script)
		for _, cmd := range cmds {
			chCmdList, chCmdAllow := checkCmd(cmd)
			cmdList = append(cmdList, chCmdList...)
			allow = allow && chCmdAllow
		}
		return
	default:
		allow = false
		return
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

func setSelfCPU(cpus string) {
	pid := os.Getpid()
	cmd := exec.Command("sudo", "taskset", "-acp", cpus, strconv.Itoa(pid))
	cmd.Run()
}

func hasCmd(cmdList []string, target string) bool {
	for _, cmd := range cmdList {
		if target == cmd {
			return true
		}
	}
	return false
}

func main() {
	sshOriginalCmd := os.Getenv("SSH_ORIGINAL_COMMAND")
	home = os.Getenv("HOME")
	cpuNum = runtime.NumCPU()
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
	if len(cmd) > 1 {
		journal.Print(journal.PriNotice, "Incorrect cmd: %v\n", sshOriginalCmd)
	} else {
		cmdList, allow := checkCmd(cmd[0])
		if allow {
			var prio int
			var cpuStr string
			if hasCmd(cmdList, "/usr/bin/x2goruncommand") {
				prio = 0
				if cpuNum > 1 {
					cpuStr = ""
					for i := 1; i < cpuNum-1; i++ {
						cpuStr = cpuStr + strconv.Itoa(i) + ","
					}
					cpuStr = cpuStr + strconv.Itoa(cpuNum-1)
				} else {
					cpuStr = "0"
				}
			} else {
				cpuStr = "0"
				prio = -11
			}
			setSelfPriority(prio)
			setSelfCPU(cpuStr)
			syscall.Exec("/bin/bash", []string{"bash", "-c", sshOriginalCmd}, os.Environ())
		} else {
			journal.Print(journal.PriNotice, "Reject cmd: %v\n", sshOriginalCmd)
		}
	}
}
