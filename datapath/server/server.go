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
	"net"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-systemd/v22/journal"
	_ "github.com/go-sql-driver/mysql"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var (
	crtFilePath  = "/usr/local/etc/dataPathServer/server.crt"
	keyFilePath  = "/usr/local/etc/dataPathServer/server.key"
	pubKeys      = []ed25519.PublicKey{}
	dbClient     *sql.DB
	ossClient    *minio.Client
	ossAccessKey = "yX61qRAWhaHcQPEXwYcQ"
	ossSecretKey = "cUzNE7CuCy53DZMtMP667ahn2Nz7eDPdJoBcUQtQ"
	ossEndpoint  = "127.0.0.1:9000"
	vpcIdList    map[int]*net.IPNet
	vpcNameList  map[string]int
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
	_, err = ossClient.ListBuckets(context.Background())
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

func loadVpcList() {
	vpcIdList = make(map[int]*net.IPNet)
	vpcNameList = make(map[string]int)
	vpcRows, err := dbClient.Query("SELECT vpc_id,cidr,vpc_name FROM vpc")
	if err != nil {
		journal.Print(journal.PriErr, "Failed to load VPC list: %v\n", err)
		return
	}
	for vpcRows.Next() {
		var id int
		var cidrStr string
		var vpcName string
		err := vpcRows.Scan(&id, &cidrStr, &vpcName)
		if err != nil || id == 0 {
			continue
		}
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			journal.Print(journal.PriErr, "Failed to parse VPC %v CIDR: %v\n", id, err)
			continue
		}
		vpcIdList[id] = cidr
		vpcNameList[vpcName] = id
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

func createNewApplication(userKey ed25519.PublicKey, srcVpcId int, dstVpcId int, sendFileList []appFile, status int16) error {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(userKey)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to marshal public key: %v", err)
		return err
	}
	user := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}))
	result, err := dbClient.Exec("INSERT INTO applications (owner,source_vpc_id,destination_vpc_id,approval_status) VALUES (?,?,?,?)", user, srcVpcId, dstVpcId, status)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to create new application: %v", err)
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		journal.Print(journal.PriErr, "Failed to get application id: %v", err)
		return err
	}
	for _, sendFile := range sendFileList {
		_, err := dbClient.Exec("INSERT INTO application_file (file_hash,application_id,file_info) VALUES (?,?,?)", sendFile.Hash, id, sendFile.RelPath)
		if err != nil {
			journal.Print(journal.PriErr, "Failed to create new application: %v", err)
			return err
		}
	}
	return nil
}

func updateFileInfo(hash string) error {
	_, err := dbClient.Exec("UPDATE files SET expiration_time=? WHERE hash=?", time.Now().AddDate(0, 30, 0), hash)
	if err != nil {
		journal.Print(journal.PriErr, "Update file database error: %v\n", err)
	}
	return err
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

func getVpcIdByIp(addrStr string) int {
	ipStr, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		return 0
	}
	addr := net.ParseIP(ipStr)
	for id, vpc := range vpcIdList {
		if vpc.Contains(addr) {
			return id
		}
	}
	return 0
}

func getVpcIdByName(vpcName string) (int, error) {
	var err error = nil
	id, exist := vpcNameList[vpcName]
	if !exist {
		id = 0
		err = fmt.Errorf("VPC %v not found, choose outside", vpcName)
	}
	return id, err
}

func uploadServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Only post method allowed."))
			return
		}
		signature, err := hex.DecodeString(r.PostFormValue("signature"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Signature missing."))
			return
		}
		dstStr := r.PostFormValue("dstName")
		jsonBytes := []byte(r.PostFormValue("jsondata"))
		user := checkSign(jsonBytes, signature)
		if user == nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unknown user signature."))
			return
		}
		var sendFileList []appFile
		err = json.Unmarshal(jsonBytes, &sendFileList)
		if err != nil {
			w.WriteHeader(http.StatusMisdirectedRequest)
			w.Write([]byte("Empty send file list."))
			return
		}
		var needFileList []string
		for _, file := range sendFileList {
			if !checkFileExist(file.Hash) {
				needFileList = append(needFileList, file.Hash)
			} else {
				err := updateFileInfo(file.Hash)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Updata file info failed."))
					return
				}
			}
		}
		src := getVpcIdByIp(r.RemoteAddr)
		dst, err := getVpcIdByName(dstStr)
		if err != nil {
			w.Header().Set("Warning", err.Error())
		}
		if dst == src {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Same src and dst."))
			return
		}
		if len(needFileList) == 0 {
			var iniStat int16 = 1
			if src == 0 {
				iniStat = 0
			}
			err := createNewApplication(user, src, dst, sendFileList, iniStat)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Create application error."))
			} else {
				w.WriteHeader(http.StatusOK)
			}
		} else {
			w.Header().Set("Content-Type", "application/json")
			returnBytes, _ := json.Marshal(needFileList)
			w.WriteHeader(http.StatusPreconditionRequired)
			w.Write(returnBytes)
		}
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Only post method allowed."))
			return
		}
		file, fileHeader, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusMisdirectedRequest)
			w.Write([]byte("Failed to load file in request."))
			return
		}
		defer file.Close()
		fileBytes, err := io.ReadAll(file)
		if err != nil {
			w.WriteHeader(http.StatusMisdirectedRequest)
			w.Write([]byte("Failed to read file in request."))
			return
		}
		signature, err := hex.DecodeString(r.PostFormValue("signature"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Signature missing."))
			return
		}
		user := checkSign(fileBytes, signature)
		if user == nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unknown user signature."))
			return
		}
		err = saveFile(fileBytes, fileHeader.Filename)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Failed to save file."))
			return
		}
	})
	return http.ListenAndServeTLS("0.0.0.0:9990", crtFilePath, keyFilePath, mux)
}

func downloadServer() error {
	mux := http.NewServeMux()

	return http.ListenAndServeTLS("0.0.0.0:9991", crtFilePath, keyFilePath, mux)
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
	loadVpcList()
	go func() {
		for {
			err := uploadServer()
			if err != nil {
				journal.Print(journal.PriErr, "Upload server error: %v\n", err)
			}
		}
	}()
	go func() {
		for {
			err := downloadServer()
			if err != nil {
				journal.Print(journal.PriErr, "Download server error: %v\n", err)
			}
		}
	}()
	for {
		fileTidy()
		time.Sleep(24 * time.Hour)
	}
}
