package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	certFilePath  = "/usr/local/etc/inbox/certs"
	certPool      = x509.NewCertPool()
	loPrivKeyPath = "./certs/privKey"
	client        *http.Client
	port          = "9990"
	loPrivKey     ed25519.PrivateKey
)

func loadCertsAndKeys() {
	filepath.Walk(certFilePath, func(path string, info fs.FileInfo, err error) error {
		if !info.Mode().IsRegular() {
			return nil
		}
		if err != nil {
			log.Printf("Failed to access %v: %v\n", path, err)
			return nil
		}
		certBytes, err := os.ReadFile(path)
		if err != nil {
			log.Printf("Failed to access %v: %v\n", path, err)
			return nil
		}
		certPool.AppendCertsFromPEM(certBytes)
		return nil
	})
	loPrivKeyByte, err := os.ReadFile(loPrivKeyPath)
	if err != nil {
		log.Printf("Failed to load private key %v: %v\n", loPrivKeyPath, err)
		return
	}
	block, _ := pem.Decode(loPrivKeyByte)
	if block == nil {
		log.Printf("Private key file incorrect: %v\n", err)
		return
	}
	tmpkey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("Failed to parse private key: %v\n", err)
		return
	}
	loPrivKey = tmpkey.(ed25519.PrivateKey)
}

type appFile struct {
	Hash    string
	RelPath string
}

func sendApplication(host string, sendFileList []appFile) *http.Response {
	host = host + "apply"
	jsonData, err := json.Marshal(sendFileList)
	if err != nil {
		log.Printf("Marshal application failed: %v\n", err)
		return nil
	}
	signature := ed25519.Sign(loPrivKey, jsonData)
	var buf bytes.Buffer
	bufWriter := multipart.NewWriter(&buf)
	bufWriter.WriteField("signature", hex.EncodeToString(signature))
	jsonField, err := bufWriter.CreateFormField("jsondata")
	if err != nil {
		log.Printf("Generate request error: %v\n", err)
		return nil
	}
	jsonField.Write(jsonData)
	bufWriter.Close()
	req, _ := http.NewRequest("POST", host, &buf)
	req.Header.Set("Content-Type", bufWriter.FormDataContentType())
	res, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send application: %v\n", err)
		return nil
	}
	return res
}

func sendFile(host string, fileHash string, fileBytes []byte) *http.Response {
	host = host + "upload"
	var buf bytes.Buffer
	bufWriter := multipart.NewWriter(&buf)

	part, err := bufWriter.CreateFormFile("file", fileHash)
	if err != nil {
		log.Printf("Generate request error: %v\n", err)
		return nil
	}
	_, err = part.Write(fileBytes)
	if err != nil {
		log.Printf("Failed to write buf: %v", err)
		return nil
	}

	bufWriter.Close()
	req, _ := http.NewRequest("POST", host, &buf)
	req.Header.Set("Content-Type", bufWriter.FormDataContentType())
	res, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send application: %v\n", err)
		return nil
	}
	return res
}

func inbox(host string, filePaths []string) {
	host = fmt.Sprintf("https://%v:%v/", host, port)
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}
	var sendFileList []appFile
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
			sendFileList = append(sendFileList, appFile{Hash: fileHash, RelPath: fileRelPath})
			return nil
		})
	}
	res := sendApplication(host, sendFileList)
	if res == nil {
		return
	}
	var needFileList []string
	tmpByte, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("Failed to load response body: %v\n", err)
		return
	}
	err = json.Unmarshal(tmpByte, &needFileList)
	if err != nil {
		log.Printf("Failed to unmarshal response body: %v\n", err)
		return
	}
	for _, filePath := range filePaths {
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
			res := sendFile(host, fileHash, fileBytes)
			fmt.Println(res)
			return nil
		})
	}
}

func main() {
	loadCertsAndKeys()
	// inbox("106.15.236.65", []string{"./certs"})
	var rootCmd = &cobra.Command{
		Use:   "inbox <host> <file(s)>",
		Short: "Send files to specified host",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("need to specify host and file")
			}
			inbox(args[0], args[1:])
			return nil
		},
	}
	rootCmd.Execute()
}
