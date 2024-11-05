package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-systemd/v22/journal"
	_ "github.com/go-sql-driver/mysql"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var (
	crtFilePath  = "./server.crt"
	keyFilePath  = "./server.key"
	pubKeys      = []ed25519.PublicKey{}
	dbClient     *sql.DB
	ossClient    *minio.Client
	ossAccessKey = "yX61qRAWhaHcQPEXwYcQ"
	ossSecretKey = "cUzNE7CuCy53DZMtMP667ahn2Nz7eDPdJoBcUQtQ"
	ossEndpoint  = "127.0.0.1:9000"
)

type appFile struct {
	Hash    string
	RelPath string
}

func connectDb() {
	var err error
	dbClient, err = sql.Open("mysql", "shizhao:icbench@tcp(127.0.0.1:3306)/data_path_server")
	if err != nil {
		journal.Print(journal.PriErr, "Failed to connect database: %v\n", err)
		os.Exit(-1)
	}
	err = dbClient.Ping()
	if err != nil {
		journal.Print(journal.PriErr, "Failed to connect database: %v\n", err)
		os.Exit(-1)
	}
}

func connectOss() {
	var err error
	certPool := x509.NewCertPool()
	certBytes := []byte("-----BEGIN CERTIFICATE-----\nMIIB4DCCAYagAwIBAgIQfaQTy1UvE2nSmVdcBt6x+DAKBggqhkjOPQQDAjA6MRww\nGgYDVQQKExNDZXJ0Z2VuIERldmVsb3BtZW50MRowGAYDVQQLDBFyb290QHh1YnVu\ndHUyNC4wNDAeFw0yNDExMDUwNjAzMThaFw0yNTExMDUwNjAzMThaMDoxHDAaBgNV\nBAoTE0NlcnRnZW4gRGV2ZWxvcG1lbnQxGjAYBgNVBAsMEXJvb3RAeHVidW50dTI0\nLjA0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt2f2CQobGLrpG9xWCCvjlfJQ\nefnwQmnEs8mnaCTC5QeAqqRz8dN9CyoFktnT76U11yhW04wHBk+g/9CDUucAG6Nu\nMGwwDgYDVR0PAQH/BAQDAgKkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB\n/wQFMAMBAf8wHQYDVR0OBBYEFLfADvpqY/Mb+uetjzilEO6bzeZQMBUGA1UdEQQO\nMAyHBH8AAAGHBGoP7EEwCgYIKoZIzj0EAwIDSAAwRQIhAOVDtvm6T0iu8CfMgPiN\nAtlBwc+qteQ4qKRv8rCk2NJTAiAeVBJJoxXPL/EvyEtVFSUYd+qgvh/ri6cJRBVV\noFmAZA==\n-----END CERTIFICATE-----")
	certPool.AppendCertsFromPEM(certBytes)
	ossClient, err = minio.New(ossEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(ossAccessKey, ossSecretKey, ""),
		Secure: true,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	})
	if err != nil {
		journal.Print(journal.PriErr, "Failed to connect OSS: %v\n", err)
		os.Exit(-1)
	}
}

func loadPubKeys() {
	keyCows, err := dbClient.Query("SELECT public_key FROM users")
	if err != nil {
		journal.Print(journal.PriErr, "Failed to get pubkey from database: %v\n", err)
		return
	}
	for keyCows.Next() {
		var keyStr string
		keyCows.Scan(&keyStr)
		pubKeyBytes := []byte(keyStr)
		block, _ := pem.Decode(pubKeyBytes)
		tmpKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			journal.Print(journal.PriErr, "Failed to parse pubkey: %v\n", err)
			continue
		}
		pubKeys = append(pubKeys, tmpKey.(ed25519.PublicKey))
	}
}

func checkFileExist(hash string) bool {
	rows, err := dbClient.Query("SELECT hash FROM files WHERE hash = ?", hash)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to query file info from database: %v\n", err)
		return false
	}
	return rows.Next()
}

func createNewApplication(userKey ed25519.PublicKey, sendFileList []appFile, status int16) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(userKey)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to marshal public key: %v", err)
		return
	}
	user := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}))
	result, err := dbClient.Exec("INSERT INTO applications (owner,approval_status) VALUES (?,?)", user, status)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to create new application: %v", err)
		return
	}
	id, err := result.LastInsertId()
	if err != nil {
		journal.Print(journal.PriErr, "Failed to get application id: %v", err)
		return
	}
	for _, sendFile := range sendFileList {
		_, err := dbClient.Exec("INSERT INTO application_file (file_hash,application_id,file_info) VALUES (?,?,?)", sendFile.Hash, id, sendFile.RelPath)
		if err != nil {
			journal.Print(journal.PriErr, "Failed to create new application: %v", err)
			return
		}
	}
}

func saveFile(fileBytes []byte, hash string) error {
	ctx := context.Background()
	_, err := ossClient.PutObject(ctx, "files", hash, bytes.NewReader(fileBytes), int64(len(fileBytes)), minio.PutObjectOptions{})
	if err != nil {
		journal.Print(journal.PriErr, "Save file to oss error: %v\n", err)
		return err
	}
	expTime := time.Now().AddDate(0, 30, 0)
	_, err = dbClient.Exec("INSERT INTO files (hash,expiration_time) VALUES (?,?)", hash, expTime)
	if err != nil {
		journal.Print(journal.PriErr, "Update file database error: %v\n", err)
		return err
	}
	return nil
}

func delFile(hash string) {
	ctx := context.Background()
	err := ossClient.RemoveObject(ctx, "files", hash, minio.RemoveObjectOptions{})
	if err != nil {
		journal.Print(journal.PriErr, "Delete file in oss error: %v\n", err)
	}
}

func checkSign(dataBytes []byte, signature []byte) ed25519.PublicKey {
	for _, pubKey := range pubKeys {
		if ok := ed25519.Verify(pubKey, dataBytes, signature); ok {
			return pubKey
		}
	}
	return nil
}

func isIntranet(addr string) bool {
	return addr == ""
}

func uploadServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/apply", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.RemoteAddr)
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		signature, err := hex.DecodeString(r.PostFormValue("signature"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		jsonBytes := []byte(r.PostFormValue("jsondata"))
		user := checkSign(jsonBytes, signature)
		if user == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var sendFileList []appFile
		err = json.Unmarshal(jsonBytes, &sendFileList)
		if err != nil {
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		var needFileList []string
		for _, file := range sendFileList {
			if !checkFileExist(file.Hash) {
				needFileList = append(needFileList, file.Hash)
			}
		}
		if len(needFileList) == 0 {
			var iniStat int16
			if isIntranet(r.RemoteAddr) {
				iniStat = 0
			} else {
				iniStat = 1
			}
			createNewApplication(user, sendFileList, iniStat)
		}
		w.Header().Set("Content-Type", "application/json")
		returnBytes, _ := json.Marshal(needFileList)
		w.Write(returnBytes)
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		file, fileHeader, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		defer file.Close()
		fileBytes, err := io.ReadAll(file)
		if err != nil {
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		signature, err := hex.DecodeString(r.PostFormValue("signature"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		user := checkSign(fileBytes, signature)
		if user == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		err = saveFile(fileBytes, fileHeader.Filename)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})
	return http.ListenAndServeTLS("0.0.0.0:9990", crtFilePath, keyFilePath, mux)
}

func downloadServer() {
	mux := http.NewServeMux()

	http.ListenAndServeTLS("0.0.0.0:9991", crtFilePath, keyFilePath, mux)
}

func fileTidy() {
	outdatedFileRow, err := dbClient.Query("SELECT hash FROM files WHERE expiration_time < ?", time.Now())
	if err != nil {
		journal.Print(journal.PriErr, "Error while trying to tidy files: %v\n", err)
		return
	}
	var delReqList = make(map[int]struct{})
	var delFileList = make(map[string]struct{})
	for outdatedFileRow.Next() {
		var hash string
		outdatedFileRow.Scan(&hash)
		delFile(hash)
		delFileList[hash] = struct{}{}
		outdatedReqRow, err := dbClient.Query("SELECT application_id FROM application_file WHERE file_hash = ?", hash)
		if err != nil {
			journal.Print(journal.PriErr, "Error while trying to tidy applications: %v\n", err)
			return
		}
		for outdatedReqRow.Next() {
			var id int
			outdatedReqRow.Scan(&id)
			delReqList[id] = struct{}{}
		}
	}
	for req := range delReqList {
		dbClient.Exec("DELETE FROM applications WHERE id = ?", req)
	}
	for file := range delFileList {
		dbClient.Exec("DELETE FROM files WHERE hash = ?", file)
	}
}

func main() {
	connectDb()
	connectOss()
	loadPubKeys()
	go func() {
		for {
			err := uploadServer()
			if err != nil {
				journal.Print(journal.PriErr, "Upload server error: %v\n", err)
			}
		}
	}()
	go downloadServer()
	for {
		fileTidy()
		time.Sleep(24 * time.Hour)
	}
}
