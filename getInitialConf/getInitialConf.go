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

type inputFile struct {
	Path   []string
	Filter string
}

type config struct {
	Data   []fileConf
	DryRun bool
}

type fileConf struct {
	Path string
	Hash []string
}

var data []fileConf

func getFileSHA256(path string) (string, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	fileSHA := sha256.Sum256(file)
	return hex.EncodeToString(fileSHA[:]), nil
}

func getFileConf(file string) {
	info, err := os.Stat(file)
	if err != nil {
		log.Printf("Access %v error: %v\n", file, err)
		return
	}
	if info.IsDir() {
		log.Printf("%v is a directory!\n", file)
		return
	}
	path, err := filepath.Abs(file)
	if err != nil {
		log.Printf("Get %v config failed: %v\n", file, err)
		return
	}
	fileHash, err := getFileSHA256(path)
	if err != nil {
		log.Printf("Get %v hash failed: %v\n", file, err)
		return
	}
	data = append(data, fileConf{Path: path, Hash: []string{fileHash}})
}

func getDirConfig(dir string, filter string) {
	info, err := os.Stat(dir)
	if err != nil {
		log.Printf("Access %v error: %v", dir, err)
		return
	}
	if !info.IsDir() {
		log.Printf("%v is not a directory!", dir)
		return
	}
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

func getConfig(path string, filter string) {
	info, err := os.Stat(path)
	if err != nil {
		log.Printf("Access %v error: %v", path, err)
		return
	}
	if info.IsDir() {
		getDirConfig(path, filter)
	} else {
		getFileConf(path)
	}
}

func createConfFile(data []fileConf, path string) {
	var conf = config{
		Data:   data,
		DryRun: true,
	}
	dataBytes, err := yaml.Marshal(conf)
	if err != nil {
		log.Printf("Marshal config err: %v", err)
		os.Exit(-1)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
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
	var filter string
	var ouputFile string
	var configFile string
	var rootCmd = &cobra.Command{
		Use:   "getInitialConf",
		Short: "Get initial unsigned config for watchdog, only used to get file config",
		Run: func(cmd *cobra.Command, args []string) {
			if cmd.Flags().Changed("input") {
				var inputs []inputFile
				inputByte, err := os.ReadFile(configFile)
				if err != nil {
					log.Printf("Access %v error: %v\n", configFile, err)
					os.Exit(-1)
				}
				yaml.Unmarshal(inputByte, &inputs)
				for _, input := range inputs {
					for _, path := range input.Path {
						getConfig(path, input.Filter)
					}
				}
			} else {
				for _, arg := range args {
					getConfig(arg, filter)
				}
			}
			createConfFile(data, ouputFile)
		},
	}
	rootCmd.PersistentFlags().StringVarP(&ouputFile, "output", "o", "watchdog.yaml", "Specify the output file")
	rootCmd.PersistentFlags().StringVarP(&filter, "filter", "f", "", "Filter files by name, will not take effect on the specified file")
	rootCmd.PersistentFlags().StringVarP(&configFile, "input", "i", "", "Use a file as input to specify file, directory and filter, other specified file, directory or filter will be ignored")

	var completion = &cobra.Command{
		Use: "completion",
	}
	completion.Hidden = true
	rootCmd.AddCommand(completion)
	rootCmd.Execute()
}
