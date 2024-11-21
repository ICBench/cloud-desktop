package main

import (
	"context"
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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	loUserName    string
	serverHost    string
	configPath    = "/usr/local/etc/dataPathClient/config.yaml"
	caPoolPath    = "/usr/local/etc/dataPathClient/CApool"
	crtFilePath   = "/usr/local/etc/dataPathClient/cert/client.crt"
	keyFilePath   = "/usr/local/etc/dataPathClient/cert/client.key"
	loPrivKeyPath = "/usr/local/etc/dataPathClient/privKey"
	caPool        = x509.NewCertPool()
	client        = &http.Client{}
	loPrivKey     = ed25519.PrivateKey{}
	retryTime     = 10
)

func sendApplication(sendFileList []utils.AppFile, dst string) *http.Response {
	host := fmt.Sprintf("https://%v:9990/apply", serverHost)
	jsonData, err := json.Marshal(sendFileList)
	if err != nil {
		log.Printf("Marshal application failed: %v\n", err)
		return nil
	}
	return utils.SendReq(client, host, map[string][]byte{"sendfile": jsonData, "dstname": []byte(dst)}, loUserName, &loPrivKey)
}

func inbox(filePaths []string, dst string) {
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
		res := sendApplication(sendFileList, dst)
		if res == nil {
			return
		}
		data := utils.ParseRes(res)
		switch res.StatusCode {
		case http.StatusPreconditionRequired:
			var needFileList []string
			json.Unmarshal(data["needfile"], &needFileList)
			var useIn = string(data["usein"]) == "true"
			accessKeyId := string(data["accesskeyid"])
			accessKeySecret := string(data["accesskeysecret"])
			securityToken := string(data["securitytoken"])
			ossClient := utils.NewOssClient(accessKeyId, accessKeySecret, securityToken, useIn)
			if ossClient == nil {
				log.Println("Failed to create oss client.")
				os.Exit(-1)
			}
			uploader := manager.NewUploader(ossClient)
			for _, needFile := range needFileList {
				path := filePathTmp[needFile]
				file, err := os.Open(path)
				if err != nil {
					log.Printf("Failed to access %v: %v", path, err)
					continue
				}
				defer file.Close()
				stat, _ := file.Stat()
				bar := progressbar.DefaultBytes(
					stat.Size(),
					fmt.Sprintf("Uploading %v", stat.Name()),
				)
				_, err = uploader.Upload(context.TODO(), &s3.PutObjectInput{
					Bucket: aws.String(string(data["ossbucket"])),
					Key:    aws.String(needFile),
					Body:   io.TeeReader(file, bar),
				})
				if err != nil {
					log.Printf("Failed to upload file: %v\n", stat.Name())
				}
				fmt.Println()
			}
		case http.StatusOK:
			var warning []string
			json.Unmarshal(data["warning"], &warning)
			if len(warning) > 0 {
				log.Println("Application sent succeed with warning:")
				for _, w := range warning {
					fmt.Println(w)
				}
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
	utils.LoadConfig(configPath, map[string]*string{
		"username": &loUserName,
		"host":     &serverHost,
	})
	utils.LoadCertsAndKeys(caPoolPath, caPool, loPrivKeyPath, &loPrivKey)
	utils.LoadHttpClient(crtFilePath, keyFilePath, client, caPool, 9992)
	var dst string
	var rootCmd = &cobra.Command{
		Use:   "inbox <file(s)>",
		Short: "Send files to specified host",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("requires at least 1 arg")
			}
			for _, arg := range args {
				_, err := os.Stat(arg)
				if err != nil {
					return err
				}
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			inbox(args[:], dst)
		},
	}
	rootCmd.Flags().StringVarP(&dst, "dst", "d", "", "Specify destination VPC")
	rootCmd.MarkFlagRequired("dst")
	rootCmd.Execute()
}
