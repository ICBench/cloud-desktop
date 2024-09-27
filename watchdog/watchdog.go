package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

var (
	fileList = []string{
		// watchdog
		"/usr/bin/watchdog",
		"/usr/bin/wtd_disc",
		"/usr/lib/systemd/system/watchdog.service",
		"/etc/systemd/system/multi-user.target.wants/watchdog.service",
		// ssh/sshd
		"/usr/sbin/sshd",
		"/usr/lib/systemd/system/ssh.service",
		"/etc/systemd/system/multi-user.target.wants/ssh.service",
		"/usr/lib/systemd/system/ssh.socket",
		"/etc/ssh/sshd_config",
		"/usr/bin/forceCmd",
		// x2go
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
		"/usr/bin/x2goversion",
		"/usr/lib/systemd/system/x2goserver.service",
		"/etc/systemd/system/multi-user.target.wants/x2goserver.service",
		"/etc/x2go",
		"/etc/x2go/x2go_logout.d",
		"/etc/x2go/x2gosql",
		"/etc/x2go/x2gosql/passwords",
		"/etc/x2go/Xresources",
		"/etc/x2go/Xsession.d",
		"/etc/x2go/Xsession.options.d",
	}
	pidFileList = []string{
		"/run/sshd.pid",
		"/run/x2goserver.pid",
	}
)

func freeze() {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		exec.Command("sudo", "ifconfig", iface.Name, "down").Run()
	}
	os.Exit(-1)
}

func checkFile() {
	fileList = append(fileList, pidFileList...)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Print(err)
		freeze()
	}
	defer watcher.Close()
	for _, file := range fileList {
		err = watcher.Add(file)
		if err != nil {
			log.Printf("%v:%v", file, err)
			freeze()
		}
	}
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok || event.Has(fsnotify.Chmod) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Write) || event.Has(fsnotify.Rename) {
				log.Print(event)
				freeze()
			}
		case err := <-watcher.Errors:
			log.Println(err)
			freeze()
		}
	}
}

func checkProcess() {
	var pids []int
	for _, pidFile := range pidFileList {
		file, err := os.Open(pidFile)
		if err != nil {
			log.Printf("Load pid file failed: %v", err)
			freeze()
		}
		reader := io.Reader(file)
		var pid int
		_, err = fmt.Fscanf(reader, "%d", &pid)
		if err != nil {
			log.Printf("Pid file error: %v", err)
			freeze()
		}
		pids = append(pids, pid)
	}
	for {
		for _, pid := range pids {
			if err := syscall.Kill(pid, 0); err != nil {
				log.Print("Process dead")
				freeze()
			}
		}
		time.Sleep(50 * time.Microsecond)
	}
}

func main() {
	logfile, err := os.OpenFile("/var/log/wtd/watchdog.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, os.ModePerm)
	if err != nil {
		log.Printf("Open log file Failed: %v", err)
		freeze()
	}
	multiWriter := io.MultiWriter(logfile, os.Stdout)
	log.SetOutput(multiWriter)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		checkFile()
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		checkProcess()
		wg.Done()
	}()
	wg.Wait()
}
