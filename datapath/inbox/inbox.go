package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"datapath/utils"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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

func sendFile(host string, fileHash string, fileBytes []byte) *http.Response {
	host = host + "upload"
	return utils.SendReq(client, host, map[string][]byte{"file": fileBytes, "filehash": []byte(fileHash)}, &loPrivKey)
}

func inbox(host string, filePaths []string, dst string) {
	host = fmt.Sprintf("https://%v:9990/", host)
	var sendFileList []utils.AppFile
	filePathTmp := make(map[string]string)
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
			filePathTmp[fileHash] = path
			return nil
		})
	}
	for range retryTime {
		res := sendApplication(host, sendFileList, dst)
		if res == nil {
			return
		}
		data := utils.ParseRes(res)
		switch res.StatusCode {
		case http.StatusPreconditionRequired:
			var needFileList []string
			err := json.Unmarshal(data["needfile"], &needFileList)
			if err != nil {
				log.Printf("Failed to unmarshal response body: %v\n", err)
				return
			}
			for _, needFile := range needFileList {
				path := filePathTmp[needFile]
				fileBytes, err := os.ReadFile(path)
				if err != nil {
					log.Printf("Failed to access %v: %v", path, err)
				}
				fileHashBytes := sha256.Sum256(fileBytes)
				fileHash := hex.EncodeToString(fileHashBytes[:])
				res := sendFile(host, fileHash, fileBytes)
				if res.StatusCode != http.StatusOK {
					data := utils.ParseRes(res)
					log.Printf("Send file error, http %v: %v\n", res.StatusCode, string(data["error"]))
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
	// inbox("106.15.236.65", []string{"./inbox"}, "vpc_test")
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
