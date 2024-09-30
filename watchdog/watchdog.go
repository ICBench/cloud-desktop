package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

type watchFile struct {
	Path string
	Hash []string
}

var (
	fileList    = []watchFile{}
	pidFileList = []watchFile{}
)

func getFileSHA256(path string) string {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Get path's SHA256 failed: %v\n", err)
	}
	fileSHA := sha256.Sum256(file)
	return hex.EncodeToString(fileSHA[:])
}

func checkDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		log.Printf("Load %v state failed: %v\n", path, err)
		freeze()
	}
	if !info.IsDir() {
		log.Printf("%v should be a dir\n", path)
		freeze()
	}
	return true
}

func checkHash(hashs []string, path string) {
	var f = true
	nowHash := getFileSHA256(path)
	for _, hash := range hashs {
		if hash == nowHash {
			f = false
		}
	}
	if f {
		log.Printf("File changed: %v", path)
		freeze()
	}
}

func loadConfig() {
	path := "/etc/wtd/watchdog.config"
	confBytes, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Load config error: %v", err)
		freeze()
	}
	json.Unmarshal(confBytes, &fileList)
	for _, file := range fileList {
		if strings.HasSuffix(file.Path, ".pid") {
			pidFileList = append(pidFileList, file)
			continue
		}
		if len(file.Hash) <= 0 && checkDir(file.Path) {
			continue
		}
		checkHash(file.Hash, file.Path)
	}
}

func freeze() {
	syscall.Reboot(syscall.LINUX_REBOOT_CMD_HALT)
	// 理论上不会执行接下来的退出程序，因为系统被停止了
	os.Exit(-1)
}

func checkFile() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Println(err)
		freeze()
	}
	defer watcher.Close()
	for _, file := range fileList {
		err = watcher.Add(file.Path)
		if err != nil {
			log.Printf("%v:%v\n", file, err)
			freeze()
		}
	}
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok || event.Has(fsnotify.Chmod) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Write) || event.Has(fsnotify.Rename) {
				log.Println(event)
				freeze()
			}
		case err := <-watcher.Errors:
			log.Println(err)
			freeze()
		}
	}
}

func checkProcess() {
	for {
		for _, pidFile := range pidFileList {
			file, err := os.Open(pidFile.Path)
			if err != nil {
				log.Printf("Load pid file failed: %v\n", err)
				freeze()
			}
			reader := io.Reader(file)
			var pid int
			_, err = fmt.Fscanf(reader, "%d", &pid)
			if err != nil {
				log.Printf("Pid file error: %v\n", err)
				freeze()
			}
			exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
			if err != nil {
				log.Printf("Load process path failed: %v\n", err)
				freeze()
			}
			exePath, err = filepath.Abs(exePath)
			if err != nil {
				log.Printf("Load process abs path failed: %v\n", err)
				freeze()
			}
			checkHash(pidFile.Hash, exePath)
		}
		time.Sleep(50 * time.Microsecond)
	}
}

func main() {
	loadConfig()
	logfile, err := os.OpenFile("/var/log/wtd/watchdog.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, os.ModePerm)
	if err != nil {
		log.Printf("Open log file Failed: %v\n", err)
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
