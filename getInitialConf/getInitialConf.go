package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
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

func getFileSHA256(path string) (string, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Get path's SHA256 failed: %v\n", err)
		return "", err
	}
	fileSHA := sha256.Sum256(file)
	return hex.EncodeToString(fileSHA[:]), nil
}

func getFileConf(files []string) {
	var data []fileConf
	for _, file := range files {
		path, err := filepath.Abs(file)
		if err != nil {
			log.Printf("Get %v config failed: %v", file, err)
			continue
		}
		fileHash, err := getFileSHA256(path)
		if err != nil {
			log.Printf("Get %v hash failed: %v", file, err)
			continue
		}
		data = append(data, fileConf{Path: path, Hash: []string{fileHash}})
	}
	createConfFile(data)
}

func getDirConfig(dirs []string, filter string) {
	var data []fileConf
	for _, dir := range dirs {
		filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				log.Printf("Access %v error: %v", path, err)
				return nil
			}
			if !strings.Contains(path, filter) {
				return nil
			}
			path, err = filepath.Abs(path)
			if err != nil {
				log.Printf("Get %v config failed: %v", path, err)
				return nil
			}
			if info.IsDir() {
				data = append(data, fileConf{Path: path, Hash: []string{}})
			} else {
				fileHash, err := getFileSHA256(path)
				if err != nil {
					log.Printf("Get %v hash failed: %v", path, err)
					return nil
				}
				data = append(data, fileConf{Path: path, Hash: []string{fileHash}})
			}
			return nil
		})
	}
	createConfFile(data)
}

func createConfFile(data []fileConf) {
	var conf = config{
		Data:   data,
		DryRun: true,
	}
	dataBytes, err := yaml.Marshal(conf)
	if err != nil {
		log.Printf("Marshal config err: %v", err)
		os.Exit(-1)
	}
	file, err := os.OpenFile("watchdog.yaml", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Open config file err: %v", err)
		os.Exit(-1)
	}
	_, err = file.Write(dataBytes)
	if err != nil {
		log.Printf("Write config file err: %v", err)
		os.Exit(-1)
	}
}

func main() {
	var rootCmd = &cobra.Command{Use: "getInitialConf"}

	var cmdFile = &cobra.Command{
		Use:   "file",
		Short: "Get file config",
		Long:  "Get file config, can specify multiple files",
		Run: func(cmd *cobra.Command, args []string) {
			getFileConf(args)
		},
	}

	var filter string
	var cmdDir = &cobra.Command{
		Use:   "dir",
		Short: "Get file config in a directory",
		Long:  "Get file config in a directory, can specify multiple directories",
		Run: func(cmd *cobra.Command, args []string) {
			getDirConfig(args, filter)
		},
	}
	cmdDir.Flags().StringVarP(&filter, "filter", "f", "", "filter files by name")

	var completion = &cobra.Command{
		Use: "completion",
	}
	completion.Hidden = true
	rootCmd.AddCommand(cmdFile, cmdDir, completion)
	rootCmd.Execute()
}
