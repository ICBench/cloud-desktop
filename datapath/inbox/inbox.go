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

const (
	configPath    = "/usr/local/etc/dataPathClient/config.yaml"
	caPoolPath    = "/usr/local/etc/dataPathClient/CApool"
	crtFilePath   = "/usr/local/etc/dataPathClient/cert/client.crt"
	keyFilePath   = "/usr/local/etc/dataPathClient/cert/client.key"
	loPrivKeyPath = "/usr/local/etc/dataPathClient/privKey"
)

var (
	loUserName string
	serverHost string
	caPool     = x509.NewCertPool()
	client     = &http.Client{}
	loPrivKey  = ed25519.PrivateKey{}
)

func sendApplication(sendFileList []utils.AppFile, dst string) *http.Response {
	host := fmt.Sprintf("https://%v:9990/apply", serverHost)
	jsonData, _ := json.Marshal(sendFileList)
	return utils.SendReq(client, host, map[string][]byte{"sendfile": jsonData, "dstname": []byte(dst)}, loUserName, &loPrivKey)
}

func sendCancel(appId string) {
	host := fmt.Sprintf("https://%v:9990/cancel", serverHost)
	utils.SendReq(client, host, map[string][]byte{"appid": []byte(appId)}, loUserName, &loPrivKey)
	os.Exit(1)
}

func sendComplete(appId string) *http.Response {
	host := fmt.Sprintf("https://%v:9990/complete", serverHost)
	return utils.SendReq(client, host, map[string][]byte{"appid": []byte(appId)}, loUserName, &loPrivKey)
}

func getFileSHA256(file *os.File) []byte {
	hasher := sha256.New()
	io.Copy(hasher, file)
	return hasher.Sum(nil)
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
			file, err := os.Open(path)
			if err != nil {
				log.Printf("Failed to access %v: %v", path, err)
				return err
			}
			fileHashBytes := getFileSHA256(file)
			fileHash := hex.EncodeToString(fileHashBytes)
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
		os.Exit(1)
	}
	res := sendApplication(sendFileList, dst)
	data := utils.ParseRes(res)
	if res.StatusCode != http.StatusOK {
		err := string(data["error"])
		log.Printf("Send application error: %v\n", err)
		return
	}
	accessKeyId := string(data["accesskeyid"])
	accessKeySecret := string(data["accesskeysecret"])
	securityToken := string(data["securitytoken"])
	endPoint := string(data["endpoint"])
	region := string(data["region"])
	ossClient := utils.NewOssClient(accessKeyId, accessKeySecret, securityToken, endPoint, region)
	appId := string(data["appid"])
	if ossClient == nil {
		log.Println("Failed to create oss client.")
		sendCancel(appId)
	}
	uploader := manager.NewUploader(ossClient)
	for _, sendFile := range sendFileList {
		path := filePathTmp[sendFile.Hash]
		file, err := os.Open(path)
		if err != nil {
			log.Printf("Failed to access %v: %v", path, err)
			sendCancel(appId)
		}
		defer file.Close()
		stat, _ := file.Stat()
		bar := progressbar.DefaultBytes(
			stat.Size(),
			fmt.Sprintf("Uploading %v", stat.Name()),
		)
		body := utils.FileBar{File: file, Bar: bar}
		_, err = uploader.Upload(context.TODO(), &s3.PutObjectInput{
			Bucket: aws.String(string(data["ossbucket"])),
			Key:    aws.String(appId + "/" + sendFile.Hash),
			Body:   body,
		})
		if err != nil {
			log.Printf("Failed to upload file: %v\n", stat.Name())
			sendCancel(appId)
		}
		fmt.Println()
	}
	res = sendComplete(appId)
	if res.StatusCode != http.StatusOK {
		err := string(data["error"])
		log.Printf("Send complete error: %v\n", err)
		return
	}
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
