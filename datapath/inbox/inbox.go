package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"datapath/utils"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	caPoolPath    = "/usr/local/etc/dataPathClient/CApool"
	caPool        = x509.NewCertPool()
	crtFilePath   = "/usr/local/etc/dataPathClient/certs/client.crt"
	keyFilePath   = "/usr/local/etc/dataPathClient/certs/client.key"
	loPrivKeyPath = "/usr/local/etc/dataPathClient/privKey"
	client        = &http.Client{}
	loPrivKey     = ed25519.PrivateKey{}
	retryTime     = 10
)

func sendApplication(host string, sendFileList []utils.AppFile, dst string) *http.Response {
	host = host + "apply"
	jsonData, err := json.Marshal(sendFileList)
	if err != nil {
		log.Printf("Marshal application failed: %v\n", err)
		return nil
	}
	return utils.SendReq(client, host, map[string][]byte{"sendfile": jsonData, "dstname": []byte(dst)}, &loPrivKey)
}

func sendFile(info utils.UploadFile, file *os.File) *http.Response {
	fileStat, _ := file.Stat()
	fileSize := fileStat.Size()
	bar := progressbar.DefaultBytes(fileSize, fmt.Sprintf("Uploading %v:", fileStat.Name()))
	reqBody := io.TeeReader(file, bar)
	req, _ := http.NewRequest(info.Method, info.Url, reqBody)
	for k, v := range info.Headers {
		req.Header.Add(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Failed to upload file: %v", err)
	}
	return res
}

func inbox(host string, filePaths []string, dst string) {
	host = fmt.Sprintf("https://%v:9990/", host)
	var sendFileList []utils.AppFile
	filePathTmp := make(map[string]string)
	listSize := 0
	for _, filePath := range filePaths {
		basePath := filepath.Dir(strings.TrimSuffix(filePath, "/")) + "/"
		filepath.Walk(filePath, func(path string, info fs.FileInfo, err error) error {
			if !info.Mode().IsRegular() || err != nil {
				return err
			}
			fileBytes, err := os.ReadFile(path)
			if err != nil {
				log.Printf("Failed to access %v: %v", path, err)
				return err
			}
			fileHashBytes := sha256.Sum256(fileBytes)
			fileHash := hex.EncodeToString(fileHashBytes[:])
			fileRelPath, err := filepath.Rel(basePath, path)
			if err != nil {
				log.Printf("Failed to access %v: %v", path, err)
				return err
			}
			sendFileList = append(sendFileList, utils.AppFile{Hash: fileHash, RelPath: fileRelPath})
			listSize += 32 + len(fileRelPath)
			filePathTmp[fileHash] = path
			return nil
		})
	}
	if listSize > 1<<20 {
		log.Println("Too many files, need to compress into a package")
		os.Exit(-1)
	}
	for range retryTime {
		res := sendApplication(host, sendFileList, dst)
		if res == nil {
			return
		}
		data := utils.ParseRes(res)
		switch res.StatusCode {
		case http.StatusPreconditionRequired:
			var needFileList []utils.UploadFile
			err := json.Unmarshal(data["needfile"], &needFileList)
			if err != nil {
				log.Printf("Failed to unmarshal response body: %v\n", err)
				return
			}
			for _, needFile := range needFileList {
				path := filePathTmp[needFile.Hash]
				file, err := os.Open(path)
				if err != nil {
					log.Printf("Failed to access %v: %v", path, err)
				}
				defer file.Close()
				res := sendFile(needFile, file)
				if res.StatusCode != http.StatusOK {
					log.Printf("Send file %v error, http %v\n", path, res.StatusCode)
				}
			}
		case http.StatusOK:
			warning := string(data["warning"])
			if warning != "" {
				log.Printf("Application sent succeed with warning: %v\n", warning)
			} else {
				log.Println("Application sent succeed.")
			}
			return
		default:
			err := string(data["error"])
			log.Printf("Send application error: %v\n", err)
			return
		}
	}
}

func main() {
	utils.LoadCertsAndKeys(caPoolPath, caPool, loPrivKeyPath, &loPrivKey)
	utils.LoadHttpClient(crtFilePath, keyFilePath, client, caPool, 9992)
	var dst string
	var rootCmd = &cobra.Command{
		Use:   "inbox <host> <file(s)>",
		Short: "Send files to specified host",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("need to specify host and file")
			}
			inbox(args[0], args[1:], dst)
			return nil
		},
	}
	rootCmd.Flags().StringVarP(&dst, "dst", "d", "", "Specify destination VPC")
	rootCmd.Execute()
}
