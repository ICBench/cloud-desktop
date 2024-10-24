package main

import (
	"archive/zip"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/journal"
	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

type config struct {
	Data   []fileConf
	DryRun bool
}

type fileConf struct {
	Path string
	Hash []string
}

var (
	fileWatcherChan = make(chan map[string][]string)
	procWatcherChan = make(chan map[string][]string)
	dryRun          = false
	confPath        = "/usr/local/etc/"
	confName        = "watchdog.conf"
	publicKeyBytes  = []byte("-----BEGIN PUBLIC KEY-----\nMIIBCgKCAQEArqMEYheq+c4eFWFJbVuVq8FRn53IMqpssL/5b6SJ/zddiyOG9LeC\nt7bYjEQkYo4KN/dYIayQ8KDHJXfCxnsl+438m8/4rkQE3G+M8dICwoiHNYPxEzVe\nFKVM158aFmONTQbjZfGHKQAR0O6iDkLckL1Stiwxekt+09Yl8bjzM1we4FBbOoq5\npwJxCLnhlctQvj/pPSJQ2pkxPRR7qp/6exafSRPnj03F4FmoKGqccs4+H9RK/7S+\n94jRYvPktpolvOcfoVLF8r8QN8/fOMhznmhFm86l1opVpwNUajvWRJOKFeRc4Yns\nIbs+o8tqm2hSs1ITgM9zbNTdgQ360QgzrwIDAQAB\n-----END PUBLIC KEY-----\n")
)

func freeze() {
	if dryRun {
		journal.Print(journal.PriAlert, "Freeze!\n")
	} else {
		syscall.Reboot(syscall.LINUX_REBOOT_CMD_HALT)
		// 理论上不会执行接下来的退出程序，因为系统被停止了
		os.Exit(-1)
	}
}

func getFileSHA256(path string) (string, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	fileSHA := sha256.Sum256(file)
	return hex.EncodeToString(fileSHA[:]), nil
}

func checkDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		journal.Print(journal.PriAlert, "Load %v state failed: %v\n", path, err)
		freeze()
		return false
	}
	return info.IsDir()
}

func checkHash(hashs []string, path string) {
	var f = true
	nowHash, err := getFileSHA256(path)
	if err != nil {
		journal.Print(journal.PriAlert, "Get path's SHA256 failed: %v\n", err)
		freeze()
		return
	}
	for _, hash := range hashs {
		if hash == nowHash {
			f = false
		}
	}
	if f {
		journal.Print(journal.PriAlert, "File changed: %v", path)
		freeze()
	}
}

func checkSign(confByte []byte, signature string) {
	block, rest := pem.Decode(publicKeyBytes)
	if len(rest) != 0 || block == nil {
		journal.Print(journal.PriAlert, "Decode public key failed\n")
		freeze()
		return
	}
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		journal.Print(journal.PriAlert, "Parse public key failed: %v\n", err)
		freeze()
		return
	}
	hash := sha256.Sum256(confByte)
	signbytes, err := hex.DecodeString(signature)
	if err != nil {
		journal.Print(journal.PriAlert, "Decode signayure failed: %v\n", err)
		freeze()
		return
	}
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signbytes)
	if err != nil {
		journal.Print(journal.PriAlert, "Signature authentication failed: %v\n", err)
		freeze()
		return
	}
}

func loadConfig() (fileList map[string][]string, procList map[string][]string) {
	var conf config
	var signature string
	var confByte []byte
	procList = make(map[string][]string)
	fileList = make(map[string][]string)
	zipReader, err := zip.OpenReader(confPath + confName)
	if err != nil {
		journal.Print(journal.PriAlert, "Config file error: %v\n", err)
		freeze()
		return
	}
	defer zipReader.Close()
	signatureFile, err := zipReader.Open("watchdog.sig")
	if err != nil {
		journal.Print(journal.PriAlert, "Load signature file failed: %v\n", err)
		freeze()
		return
	}
	defer signatureFile.Close()
	signatureByte, err := io.ReadAll(signatureFile)
	if err != nil {
		journal.Print(journal.PriAlert, "Load signature failed: %v\n", err)
		freeze()
		return
	}
	signature = string(signatureByte)
	configFile, err := zipReader.Open("watchdog.yaml")
	if err != nil {
		journal.Print(journal.PriAlert, "Load config file failed: %v\n", err)
		freeze()
		return
	}
	defer configFile.Close()
	confByte, err = io.ReadAll(configFile)
	if err != nil {
		journal.Print(journal.PriAlert, "Load config failed: %v\n", err)
		freeze()
		return
	}
	checkSign(confByte, signature)
	err = yaml.Unmarshal(confByte, &conf)
	if err != nil {
		journal.Print(journal.PriAlert, "Unmarshal config failed: %v\n", err)
		freeze()
		return
	}
	dryRun = conf.DryRun
	for _, file := range conf.Data {
		absPath, err := filepath.Abs(file.Path)
		if err != nil {
			journal.Print(journal.PriAlert, "Config error: %v\n", err)
			freeze()
			continue
		}
		if strings.HasSuffix(file.Path, ".pid") {
			procList[absPath] = file.Hash
		} else {
			fileList[absPath] = file.Hash
		}
	}
	return
}

func watchConfig() {
	confWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		journal.Print(journal.PriAlert, "Create config watcher error: %v\n", err)
		freeze()
		os.Exit(-1)
	}
	defer confWatcher.Close()
	err = confWatcher.Add(confPath)
	if err != nil {
		journal.Print(journal.PriAlert, "Watch config file failed: %v\n", err)
		freeze()
	}
	for {
		select {
		case event, ok := <-confWatcher.Events:
			if !ok {
				journal.Print(journal.PriAlert, "Config watcher error!\n")
				freeze()
				os.Exit(-1)
			}
			if (event.Has(fsnotify.Write) || event.Has(fsnotify.Create)) && filepath.Base(event.Name) == confName {
				journal.Print(journal.PriNotice, "Config file change: %v\n", event)
				fileList, procList := loadConfig()
				fileWatcherChan <- fileList
				procWatcherChan <- procList
				journal.Print(journal.PriNotice, "Config change complete!\n")
			}
		case err := <-confWatcher.Errors:
			journal.Print(journal.PriAlert, "Config watcher error: %v\n", err)
			freeze()
			os.Exit(-1)
		}
	}
}

func watchFile() {
	fileWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		journal.Print(journal.PriAlert, "Create file watcher error: %v\n", err)
		freeze()
		os.Exit(-1)
	}
	watchedFile := make(map[string][]string)
	for {
		select {
		case event, ok := <-fileWatcher.Events:
			if !ok {
				journal.Print(journal.PriAlert, "File watcher error!\n")
				freeze()
				os.Exit(-1)
			}
			path, _ := filepath.Abs(event.Name)
			_, exist := watchedFile[filepath.Dir(path)]
			if exist {
				journal.Print(journal.PriAlert, "File changed: %v\n", event)
				freeze()
				continue
			}
			hashs, exist := watchedFile[path]
			if !exist {
				continue
			}
			if len(hashs) <= 0 {
				journal.Print(journal.PriAlert, "File changed: %v\n", event)
				freeze()
				continue
			} else {
				if checkDir(path) {
					journal.Print(journal.PriAlert, "%v is a dir\n", path)
					freeze()
					continue
				}
				if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) {
					checkHash(hashs, path)
				} else {
					journal.Print(journal.PriAlert, "File changed: %v\n", event)
					freeze()
					continue
				}
			}
		case err := <-fileWatcher.Errors:
			journal.Print(journal.PriAlert, "File watcher error: %v\n", err)
			freeze()
			os.Exit(-1)
		case newWatchFile := <-fileWatcherChan:
			watchedFile = make(map[string][]string)
			newWatchDir := make(map[string]struct{})
			for path, hashs := range newWatchFile {
				if len(hashs) <= 0 {
					if !checkDir(path) {
						journal.Print(journal.PriAlert, "%v should be a dir\n", path)
						freeze()
						continue
					}
					newWatchDir[path] = struct{}{}
				} else {
					checkHash(hashs, path)
					newWatchDir[filepath.Dir(path)] = struct{}{}
				}
				watchedFile[path] = hashs
			}
			watchedDir := fileWatcher.WatchList()
			for _, path := range watchedDir {
				if _, exist := newWatchDir[path]; exist {
					delete(newWatchDir, path)
				} else {
					err := fileWatcher.Remove(path)
					if err != nil {
						journal.Print(journal.PriAlert, "Update file watcher failed: %v\n", err)
						freeze()
						continue
					}
				}
			}
			for path := range newWatchDir {
				err := fileWatcher.Add(path)
				if err != nil {
					journal.Print(journal.PriAlert, "Update file watcher failed: %v\n", err)
					freeze()
					continue
				}
			}
		}
	}
}

func watchProc() {
	procWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		journal.Print(journal.PriAlert, "Create process watcher error: %v\n", err)
		freeze()
		os.Exit(-1)
	}
	procList := make(map[string][]string)
	for {
		select {
		case event, ok := <-procWatcher.Events:
			if !ok {
				journal.Print(journal.PriAlert, "Process watcher error!\n")
				freeze()
				os.Exit(-1)
			}
			if event.Has(fsnotify.Chmod) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Write) || event.Has(fsnotify.Rename) {
				path, _ := filepath.Abs(event.Name)
				file, err := os.Open(path)
				if err != nil {
					journal.Print(journal.PriAlert, "Load pid file failed: %v\n", err)
					freeze()
					continue
				}
				reader := io.Reader(file)
				var pid int
				_, err = fmt.Fscanf(reader, "%d", &pid)
				if err != nil {
					journal.Print(journal.PriAlert, "Pid file error: %v\n", err)
					freeze()
					continue
				}
				exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
				if err != nil {
					journal.Print(journal.PriAlert, "Load process path failed: %v\n", err)
					freeze()
					continue
				}
				exePath, err = filepath.Abs(exePath)
				if err != nil {
					journal.Print(journal.PriAlert, "Load process abs path failed: %v\n", err)
					freeze()
					continue
				}
				checkHash(procList[path], exePath)
			}
		case err := <-procWatcher.Errors:
			journal.Print(journal.PriAlert, "Process watcher error: %v\n", err)
			freeze()
			os.Exit(-1)
		case newWatchProc := <-procWatcherChan:
			procList = newWatchProc
			watchedProc := procWatcher.WatchList()
			for _, proc := range watchedProc {
				if _, exist := newWatchProc[proc]; exist {
					delete(newWatchProc, proc)
				} else {
					err := procWatcher.Remove(proc)
					if err != nil {
						journal.Print(journal.PriAlert, "Update process watcher failed: %v\n", err)
						freeze()
						continue
					}
				}
			}
			for proc := range newWatchProc {
				err := procWatcher.Add(proc)
				if err != nil {
					journal.Print(journal.PriAlert, "Update process watcher failed: %v\n", err)
					freeze()
					continue
				}
			}
		}
	}
}

func feedDog() {
	cmd := exec.Command("sudo", "modprobe", "-r", "softdog")
	_, err := cmd.CombinedOutput()
	if err != nil {
		journal.Print(journal.PriAlert, "Install watchdog mod error!\n")
		freeze()
		os.Exit(-1)
	}
	cmd = exec.Command("sudo", "modprobe", "softdog",
		"soft_margin=1",
		"soft_noboot=0",
		"nowayout=1",
	)
	_, err = cmd.CombinedOutput()
	if err != nil {
		journal.Print(journal.PriAlert, "Install watchdog mod error!\n")
		freeze()
		os.Exit(-1)
	}
	softdog, err := os.OpenFile("/dev/watchdog", os.O_WRONLY, 0)
	if err != nil {
		journal.Print(journal.PriAlert, "Access watchdog device error!\n")
		freeze()
		os.Exit(-1)
	}
	for {
		softdog.Write([]byte{1})
		time.Sleep(500 * time.Millisecond)
	}
}

func main() {
	if !journal.Enabled() {
		freeze()
		os.Exit(-1)
	}
	go watchFile()
	go watchProc()
	fileList, procList := loadConfig()
	fileWatcherChan <- fileList
	procWatcherChan <- procList
	go watchConfig()
	feedDog()
}
