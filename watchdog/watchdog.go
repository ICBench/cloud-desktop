package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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

type config struct {
	Data      []watchFile
	Signature string
}

type watchFile struct {
	Path string
	Hash []string
}

var (
	fileList       = []watchFile{}
	pidFileList    = []watchFile{}
	confPath       = "/etc/wtd/watchdog.config"
	publicKeyBytes = []byte("-----BEGIN PUBLIC KEY-----\nMIICCgKCAgEAyckNe37ub3mI8cSgDIC7/8ok0a31law/QSwNSMdLbBPl3AUSEeCH\n4LldfwMJRkGHO3I8gbauWpA5UtX7wgLvMavFqESi5bex8CBkddETnGVq1YmX+zqU\nEUgrkvkXCrxMsjwWhZCbhI7O9FF/Z2BVwl9VUcHlPQ2sYaHdlUt13JXHu+37WFW7\nVEegjwyBoAYijndYGfQYJBtXsEo1dtBxqnsI2mXJPbVITlpsoqbxYyPUsV/5zBmo\nes6uR1M4oXZkTdCE4u7Ggt1OicwR48brPiCC4oNRrYNPZlGNeVnRwNsEi3YBKHqv\nC0LJhiK1k8MF/tS6l3SNsSfCIB0wSWhR7ELZbmFlk4q/Yga/wd2C08TX+n6CVd/c\nDYPS+HZzfLnqT2FLmnuk2DN66lhRrdAm+rNOQd92pxIEduPO5xoibvz++5icmX02\n5VN5CpwiQq9chvqb6Qpng4sLS870cDN9W7CXiUU3pc3up5HswppyhNjqH1ig0zcf\nolWQBFlMVOixsr9rkXwXrLWWZzvmB3e2pRhXd5Go7oQCZoQf03+Ju0Zc3lal7uaA\nJ4bYTolR9EJDWCvokGj7H3vsz9+/w/hoisl+MVbG5W4VAY/35xhNsQY15w6CWMbs\nMpjrRs295MWB3fdc/2Zyqh7+c1z5HlagZe0Xu67j5g6VEmqMdXmB/iUCAwEAAQ==\n-----END PUBLIC KEY-----\n")
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

func checkSign(conf config) {
	block, rest := pem.Decode(publicKeyBytes)
	if len(rest) != 0 || block == nil {
		log.Println("Decode public key failed")
		freeze()
	}
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		log.Printf("Parse public key failed: %v\n", err)
		freeze()
	}
	data := conf.Data
	dataBytes, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		log.Printf("Marshal data failed: %v\n", err)
		freeze()
	}
	hash := sha256.Sum256(dataBytes)
	signbytes, err := hex.DecodeString(conf.Signature)
	if err != nil {
		log.Printf("Decode signayure failed: %v\n", err)
		freeze()
	}
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signbytes)
	if err != nil {
		log.Printf("Signature authentication failed: %v\n", err)
		freeze()
	}
}

func loadConfig() {
	confBytes, err := os.ReadFile(confPath)
	if err != nil {
		log.Printf("Load config error: %v", err)
		freeze()
	}
	var conf config
	json.Unmarshal(confBytes, &conf)
	checkSign(conf)
	fileList = conf.Data
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
