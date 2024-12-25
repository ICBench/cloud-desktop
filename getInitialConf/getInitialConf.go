package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"
)

var (
	fileList = []string{
		// X2Go
		"/usr/bin/perl",
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
		"/etc/x2go/Xsession",
		"/etc/x2go/Xsession.options",
		"/etc/x2go/x2go_logout",
		"/etc/x2go/x2goagent.options",
		"/etc/x2go/x2gokdrive.options",
		"/etc/x2go/x2goserver.conf",
		"/etc/x2go/x2gosql/sql",
		"/usr/lib/systemd/system/x2goserver.service",
		"/etc/systemd/system/multi-user.target.wants/x2goserver.service",
		// ssh
		"/usr/sbin/sshd",
		"/usr/lib/systemd/system/ssh.service",
		"/etc/systemd/system/multi-user.target.wants/ssh.service",
		"/usr/lib/systemd/system/ssh.socket",
		"/etc/ssh/sshd_config",
		// watchdog
		"/usr/lib/systemd/system/watchdog.service",
		"/etc/systemd/system/multi-user.target.wants/watchdog.service",
		// other
		"/usr/bin/echo",
		"/usr/bin/bash",
		"/usr/bin/scp",
		"/usr/bin/setsid",
	}
	dirList = []string{
		"/etc/x2go",
		"/etc/x2go/Xresources",
		"/etc/x2go/Xsession.d",
		"/etc/x2go/Xsession.options.d",
		"/etc/x2go/x2go_logout.d",
		"/etc/x2go/x2gosql",
		"/etc/x2go/x2gosql/passwords",
	}
	procList = []procPair{
		{PidPath: "/run/x2goserver.pid", ExePath: "/usr/bin/perl"},
		{"/run/sshd.pid", "/usr/sbin/sshd"},
	}
)

type procPair struct {
	PidPath string
	ExePath string
}

type config struct {
	Data   []fileConf
	DryRun bool
}

type fileConf struct {
	Path string
	Hash []string
}

func getFileSHA256(path string) (string, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	fileSHA := sha256.Sum256(file)
	return hex.EncodeToString(fileSHA[:]), nil
}

func getConfig(inputPath, outputPath string) {
	var newConf, oldConf config
	if inputPath != "" {
		inputByte, err := os.ReadFile(inputPath)
		if err != nil {
			log.Printf("Access %v error: %v\n", inputPath, err)
			os.Exit(-1)
		}
		toml.Unmarshal(inputByte, &oldConf)
	}

	var conf = make(map[string]map[string]struct{})
	for _, oldFileConf := range oldConf.Data {
		conf[oldFileConf.Path] = make(map[string]struct{})
		for _, hash := range oldFileConf.Hash {
			conf[oldFileConf.Path][hash] = struct{}{}
		}
	}
	for _, iniPath := range fileList {
		absPath, err := filepath.Abs(iniPath)
		if err != nil {
			log.Printf("Get file %v abs path err: %v\n", iniPath, err)
			continue
		}
		hash, err := getFileSHA256(absPath)
		if err != nil {
			log.Printf("Access file %v err: %v\n", iniPath, err)
			continue
		}
		if _, exist := conf[absPath]; !exist {
			conf[absPath] = make(map[string]struct{})
		}
		conf[absPath][hash] = struct{}{}
	}
	for _, iniPath := range dirList {
		absPath, err := filepath.Abs(iniPath)
		if err != nil {
			log.Printf("Get dir %v abs path err: %v\n", iniPath, err)
			continue
		}
		conf[absPath] = map[string]struct{}{}
	}
	for _, proc := range procList {
		absPidPath, err := filepath.Abs(proc.PidPath)
		if err != nil {
			log.Printf("Get process pid file %v abs path err: %v\n", proc.PidPath, err)
			continue
		}
		absExePath, err := filepath.Abs(proc.ExePath)
		if err != nil {
			log.Printf("Get exe file %v abs path err: %v\n", proc.ExePath, err)
			continue
		}
		hash, err := getFileSHA256(absExePath)
		if err != nil {
			log.Printf("Access exe file %v err: %v\n", absExePath, err)
			continue
		}
		if _, exist := conf[absPidPath]; !exist {
			conf[absPidPath] = make(map[string]struct{})
		}
		conf[absPidPath][hash] = struct{}{}
	}

	for path, hashs := range conf {
		var newFileConf fileConf
		newFileConf.Path = path
		for hash := range hashs {
			newFileConf.Hash = append(newFileConf.Hash, hash)
		}
		newConf.Data = append(newConf.Data, newFileConf)
	}
	newConf.DryRun = false
	outputByte, err := toml.Marshal(newConf)
	if err != nil {
		log.Printf("Marshal config err: %v", err)
		os.Exit(-1)
	}
	err = os.WriteFile(outputPath, outputByte, 0644)
	if err != nil {
		log.Printf("Write config file err: %v", err)
		os.Exit(-1)
	}
}

func main() {
	var inputPath, outputPath string
	var rootCmd = &cobra.Command{
		Use:   "getInitialConf",
		Short: "Get initial unsigned config for watchdog",
		Run: func(cmd *cobra.Command, args []string) {
			getConfig(inputPath, outputPath)
		},
	}
	rootCmd.Flags().StringVarP(&inputPath, "input", "i", "", "Specify input file path, usually the old config file")
	rootCmd.Flags().StringVarP(&outputPath, "output", "o", "watchdog.toml", "Specify output file path")
	var completion = &cobra.Command{
		Use: "completion",
	}
	completion.Hidden = true
	rootCmd.AddCommand(completion)
	rootCmd.Execute()
}
