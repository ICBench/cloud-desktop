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
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/coreos/go-systemd/v22/journal"
	_ "github.com/go-sql-driver/mysql"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var (
	caPoolPath   = "/usr/local/etc/dataPathServer/CApool"
	caPool       = x509.NewCertPool()
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
	vpcList      map[int]string
)

type appFile struct {
	Hash    string
	RelPath string
}

type appRow struct {
	Id       int
	User     string
	Status   int8
	Src, Dst string
}

func loadCerts() {
	filepath.Walk(caPoolPath, func(path string, info fs.FileInfo, err error) error {
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
		caPool.AppendCertsFromPEM(certBytes)
		return nil
	})
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
	vpcList = make(map[int]string)
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
		if err != nil {
			continue
		}
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			journal.Print(journal.PriErr, "Failed to parse VPC %v CIDR: %v\n", id, err)
			continue
		}
		vpcIdList[id] = cidr
		vpcNameList[vpcName] = id
		vpcList[id] = vpcName
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
	user := parseUserFromKey(userKey)
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

func parseUserFromKey(userKey ed25519.PublicKey) (user string) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(userKey)
	if err != nil {
		user = ""
		return
	}
	user = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}))
	return
}

func getUserInfoByKeyAndVpc(vpcId int, userKey ed25519.PublicKey) (userName string, permission int, err error) {
	user := parseUserFromKey(userKey)
	userRow := dbClient.QueryRow("SELECT user_name FROM users WHERE public_key = ?", user)
	err = userRow.Scan(&userName)
	if err != nil {
		userName = ""
		return
	}
	perRow := dbClient.QueryRow("SELECT permission FROM vpc_user WHERE user_key = ? AND vpc_id = ?", user, vpcId)
	err = perRow.Scan(&permission)
	if err != nil {
		permission = -1
	}
	err = nil
	return
}

func inboxServer() error {
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
		userKey := checkSign(jsonBytes, signature)
		if userKey == nil {
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
			err := createNewApplication(userKey, src, dst, sendFileList, iniStat)
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
	server := &http.Server{
		Addr: ":9990",
		TLSConfig: &tls.Config{
			ClientCAs:  caPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
		Handler: mux,
	}
	return server.ListenAndServeTLS(crtFilePath, keyFilePath)
}

func parseReq(req *http.Request) (userKey ed25519.PublicKey, data map[string][]byte) {
	dataBytes, _ := hex.DecodeString(req.PostFormValue("data"))
	signature, _ := hex.DecodeString(req.PostFormValue("signature"))
	userKey = checkSign(dataBytes, signature)
	jsonData := make(map[string]string)
	data = make(map[string][]byte)
	json.Unmarshal(dataBytes, &jsonData)
	for fieldName, fieldValue := range jsonData {
		data[fieldName], _ = hex.DecodeString(fieldValue)
	}
	return
}

func writeRes(res http.ResponseWriter, statusCode int, data map[string][]byte) {
	jsonData := make(map[string]string)
	for fieldName, fieldValue := range data {
		jsonData[fieldName] = hex.EncodeToString(fieldValue)
	}
	jsonBytes, _ := json.Marshal(jsonData)
	res.WriteHeader(statusCode)
	res.Write(jsonBytes)
}

func outboxServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/self", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		userKey, _ := parseReq(r)
		if userKey == nil {
			writeRes(w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		vpcId := getVpcIdByIp(r.RemoteAddr)
		userName, permission, err := getUserInfoByKeyAndVpc(vpcId, userKey)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown user.")})
			return
		}
		writeRes(w, http.StatusOK, map[string][]byte{
			"vpc":        []byte(vpcList[vpcId]),
			"username":   []byte(userName),
			"permission": []byte(strconv.Itoa(permission)),
		})
	})
	mux.HandleFunc("/applist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		userKey, _ := parseReq(r)
		user := parseUserFromKey(userKey)
		vpcId := getVpcIdByIp(r.RemoteAddr)
		_, permission, err := getUserInfoByKeyAndVpc(vpcId, userKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var appRows *sql.Rows
		if permission == 1 {
			appRows, err = dbClient.Query("select applications.id,users.user_name,applications.source_vpc_id,applications.destination_vpc_id,applications.approval_status from applications inner join users on applications.owner=users.public_key WHERE applications.source_vpc_id=?", vpcId)
		} else {
			appRows, err = dbClient.Query("select applications.id,users.user_name,applications.source_vpc_id,applications.destination_vpc_id,applications.approval_status from applications inner join users on applications.owner=users.public_key WHERE applications.owner=?", user)
		}
		if err != nil {
			journal.Print(journal.PriErr, "Failed to query application info from database: %v\n", err)
			return
		}
		var appList []appRow
		for appRows.Next() {
			var tmpApp appRow
			var srcId, dstId int
			appRows.Scan(&tmpApp.Id, &tmpApp.User, &srcId, &dstId, &tmpApp.Status)
			tmpApp.Src = vpcList[srcId]
			tmpApp.Dst = vpcList[dstId]
			appList = append(appList, tmpApp)
		}
		appListBytes, _ := json.Marshal(appList)
		writeRes(w, http.StatusOK, map[string][]byte{"applist": appListBytes})
	})
	mux.HandleFunc("/appinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		userKey, data := parseReq(r)
		idStr := string(data["id"])
		id, _ := strconv.Atoi(idStr)
		user := parseUserFromKey(userKey)
		appRow := dbClient.QueryRow("SELECT owner,destination_vpc_id FROM applications WHERE id=?", id)
		var owner string
		var dst int
		appRow.Scan(&owner, &dst)
		if user != owner {
			_, permission, _ := getUserInfoByKeyAndVpc(dst, userKey)
			if permission != 0 { //check permission,need accomplish
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("User have no permission."))
				return
			}
		}
		appFileRow, _ := dbClient.Query("SELECT file_info,file_hash FROM application_file WHERE application_id=?", id)
		var appInfo []appFile
		for appFileRow.Next() {
			var tmpInfo appFile
			appFileRow.Scan(&tmpInfo.RelPath, &tmpInfo.Hash)
			appInfo = append(appInfo, tmpInfo)
		}
		appInfoBytes, _ := json.Marshal(appInfo)
		writeRes(w, http.StatusOK, map[string][]byte{"appinfo": appInfoBytes})
	})
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		userKey, data := parseReq(r)
		fileHash := string(data["hash"])
		appId, _ := strconv.Atoi(string(data["appid"]))
		user := parseUserFromKey(userKey)
		appRow := dbClient.QueryRow("SELECT owner,destination_vpc_id FROM applications WHERE id=?", appId)
		var owner string
		var dst int
		appRow.Scan(&owner, &dst)
		if user != owner {
			_, permission, _ := getUserInfoByKeyAndVpc(dst, userKey)
			if permission != 0 { //check permission,need accomplish
				writeRes(w, http.StatusForbidden, map[string][]byte{"error": []byte("User have no permission.")})
				return
			}
		}
		appFileRow, _ := dbClient.Query("SELECT * FROM application_file WHERE application_id=? AND file_hash=?", appId, fileHash)
		if !appFileRow.Next() {
			writeRes(w, http.StatusBadRequest, map[string][]byte{"error": []byte("File not belong to application")})
			return
		}
		file, err := ossClient.GetObject(context.Background(), "files", fileHash, minio.GetObjectOptions{})
		log.Println(err)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("File not found")})
			return
		}
		fileBytes, _ := io.ReadAll(file)
		writeRes(w, http.StatusOK, map[string][]byte{"file": fileBytes, "hash": []byte(fileHash)})
	})
	server := &http.Server{
		Addr: ":9991",
		TLSConfig: &tls.Config{
			ClientCAs:  caPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
		Handler: mux,
	}
	return server.ListenAndServeTLS(crtFilePath, keyFilePath)
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
	loadCerts()
	connectDb()
	connectOss()
	loadPubKeys()
	loadVpcList()
	go func() {
		for {
			err := inboxServer()
			if err != nil {
				journal.Print(journal.PriErr, "Upload server error: %v\n", err)
			}
		}
	}()
	go func() {
		for {
			err := outboxServer()
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
