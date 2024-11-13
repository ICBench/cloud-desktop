package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"datapath/utils"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	caPoolPath     = "/usr/local/etc/dataPathServer/CApool"
	caPool         = x509.NewCertPool()
	crtFilePath    = "/usr/local/etc/dataPathServer/server.crt"
	keyFilePath    = "/usr/local/etc/dataPathServer/server.key"
	pubKeys        = []ed25519.PublicKey{}
	dbClient       *sql.DB
	ossClient      *minio.Client
	outOssClient   *minio.Client
	ossAccessKey   = "yX61qRAWhaHcQPEXwYcQ"
	ossSecretKey   = "cUzNE7CuCy53DZMtMP667ahn2Nz7eDPdJoBcUQtQ"
	ossEndpoint    = "127.0.0.1:9000"
	outOssEndpoint = "106.15.236.65:9000"
	vpcIdList      map[int]*net.IPNet
	vpcNameList    map[string]int
	vpcList        map[int]string
)

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
	outOssClient, err = minio.New(outOssEndpoint, &minio.Options{
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
	_, err = outOssClient.ListBuckets(context.Background())
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
	if rows.Next() {
		return true
	} else {
		_, err := ossClient.StatObject(context.Background(), "files", hash, minio.GetObjectOptions{})
		if err != nil {
			return false
		}
		expTime := time.Now().AddDate(0, 30, 0)
		_, err = dbClient.Exec("INSERT INTO files (hash,expiration_time) VALUES (?,?)", hash, expTime)
		if err != nil {
			journal.Print(journal.PriErr, "Update file database error: %v\n", err)
		}
		return true
	}
}

func hasReviewPer(permission int) bool {
	return permission&utils.PerReview != 0 || hasAdminPer(permission)
}

func hasAdminPer(permission int) bool {
	return permission&utils.PerAdmin != 0
}

func isAppStatAllow(status int) bool {
	return status == 0
}

func createNewApplication(userKey ed25519.PublicKey, srcVpcId int, dstVpcId int, sendFileList []utils.AppFile, status int) error {
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

func getPreSignedUploadUrl(fileName string) (string, error) {
	url, err := outOssClient.PresignedPutObject(context.Background(), "files", fileName, 1*time.Hour)
	return url.String(), err
}

func getPreSignedDownloadUrl(fileName string) (string, error) {
	url, err := outOssClient.PresignedGetObject(context.Background(), "files", fileName, 1*time.Hour, nil)
	return url.String(), err
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
	loadPubKeys()
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
		permission = 0
	}
	err = nil
	return
}

func reviewApp(idStr string, userKey ed25519.PublicKey, statusStr string) error {
	id, _ := strconv.Atoi(idStr)
	status, _ := strconv.Atoi(statusStr)
	appRows := dbClient.QueryRow("SELECT destination_vpc_id FROM applications WHERE id=?", id)
	var dstVpcId int
	err := appRows.Scan(&dstVpcId)
	if err != nil {
		return fmt.Errorf("no application %v", idStr)
	}
	_, permission, err := getUserInfoByKeyAndVpc(dstVpcId, userKey)
	user := parseUserFromKey(userKey)
	if err != nil {
		return fmt.Errorf("internal server error: unknown user")
	}
	if !hasReviewPer(permission) {
		return fmt.Errorf("no permission")
	}
	_, err = dbClient.Exec("UPDATE applications SET approval_status=?,reviewer=? WHERE id=?", status, user, id)
	if err != nil {
		return fmt.Errorf("failed to update database")
	}
	return nil
}

func parseReq(req *http.Request) (userKey ed25519.PublicKey, data map[string][]byte) {
	req.ParseMultipartForm(2 << 30)
	dataBytes, _ := hex.DecodeString(req.PostFormValue("data"))
	signature, _ := hex.DecodeString(req.PostFormValue("signature"))
	userKey = checkSign(dataBytes, signature)
	if userKey == nil {
		data = nil
		return
	}
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

func inboxServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		userKey, data := parseReq(r)
		if userKey == nil {
			writeRes(w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		dstStr := string(data["dstname"])
		var sendFileList []utils.AppFile
		err := json.Unmarshal(data["sendfile"], &sendFileList)
		if err != nil {
			writeRes(w, http.StatusMisdirectedRequest, map[string][]byte{"error": []byte("Empty send file list.")})
			return
		}
		var needFileList []utils.UploadFile
		for _, file := range sendFileList {
			if !checkFileExist(file.Hash) {
				url, err := getPreSignedUploadUrl(file.Hash)
				if err != nil {
					writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to get presigned url")})
					return
				}
				needFileList = append(needFileList, utils.UploadFile{Hash: file.Hash, Url: url})
			} else {
				err := updateFileInfo(file.Hash)
				if err != nil {
					writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Update file info failed.")})
					return
				}
			}
		}
		src := getVpcIdByIp(r.RemoteAddr)
		dst, err := getVpcIdByName(dstStr)
		var warning string = ""
		if err != nil {
			warning = err.Error()
		}
		if dst == src {
			writeRes(w, http.StatusBadRequest, map[string][]byte{"error": []byte("Same src and dst.")})
			return
		}
		if len(needFileList) == 0 {
			var iniStat int = 1
			if src == 0 {
				iniStat = 0
			}
			err := createNewApplication(userKey, src, dst, sendFileList, iniStat)
			if err != nil {
				writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Create application error.")})
				return
			} else {
				writeRes(w, http.StatusOK, map[string][]byte{"warning": []byte(warning)})
				return
			}
		} else {
			returnBytes, _ := json.Marshal(needFileList)
			writeRes(w, http.StatusPreconditionRequired, map[string][]byte{"needfile": returnBytes})
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
		if userKey == nil {
			writeRes(w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		user := parseUserFromKey(userKey)
		vpcId := getVpcIdByIp(r.RemoteAddr)
		_, permission, err := getUserInfoByKeyAndVpc(vpcId, userKey)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown user.")})
			return
		}
		var appRows *sql.Rows
		if hasReviewPer(permission) {
			appRows, err = dbClient.Query("select applications.id,users.user_name,applications.source_vpc_id,applications.destination_vpc_id,applications.approval_status from applications inner join users on applications.owner=users.public_key WHERE applications.source_vpc_id=?", vpcId)
		} else {
			appRows, err = dbClient.Query("select applications.id,users.user_name,applications.source_vpc_id,applications.destination_vpc_id,applications.approval_status from applications inner join users on applications.owner=users.public_key WHERE applications.owner=?", user)
		}
		if err != nil {
			journal.Print(journal.PriErr, "Failed to query application info from database: %v\n", err)
			return
		}
		var appList []utils.AppInfo
		for appRows.Next() {
			var tmpApp utils.AppInfo
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
		if userKey == nil {
			writeRes(w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		idStr := string(data["id"])
		id, _ := strconv.Atoi(idStr)
		user := parseUserFromKey(userKey)
		appRows := dbClient.QueryRow("SELECT owner,destination_vpc_id FROM applications WHERE id=?", id)
		var owner string
		var dst int
		appRows.Scan(&owner, &dst)
		if user != owner {
			_, permission, err := getUserInfoByKeyAndVpc(dst, userKey)
			if err != nil {
				writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown user.")})
				return
			}
			if !hasReviewPer(permission) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("User have no permission."))
				return
			}
		}
		appFileRow, _ := dbClient.Query("SELECT file_info,file_hash FROM application_file WHERE application_id=?", id)
		var appInfo []utils.AppFile
		for appFileRow.Next() {
			var tmpInfo utils.AppFile
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
		if userKey == nil {
			writeRes(w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		fileHash := string(data["hash"])
		appId, _ := strconv.Atoi(string(data["appid"]))
		user := parseUserFromKey(userKey)
		appRows := dbClient.QueryRow("SELECT owner,destination_vpc_id,approval_status FROM applications WHERE id=?", appId)
		var owner string
		var dst int
		var status int
		appRows.Scan(&owner, &dst, &status)
		if user != owner {
			_, permission, err := getUserInfoByKeyAndVpc(dst, userKey)
			if err != nil {
				writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown user.")})
				return
			}
			if !hasReviewPer(permission) {
				writeRes(w, http.StatusForbidden, map[string][]byte{"error": []byte("User has no permission.")})
				return
			}
		} else {
			if !isAppStatAllow(status) {
				writeRes(w, http.StatusForbidden, map[string][]byte{"error": []byte("Application unreviewed, connect leader")})
				return
			}
		}
		appFileRow, _ := dbClient.Query("SELECT * FROM application_file WHERE application_id=? AND file_hash=?", appId, fileHash)
		if !appFileRow.Next() {
			writeRes(w, http.StatusBadRequest, map[string][]byte{"error": []byte("File not belong to application")})
			return
		}
		url, err := getPreSignedDownloadUrl(fileHash)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("File not found")})
			return
		}
		writeRes(w, http.StatusOK, map[string][]byte{"url": []byte(url), "hash": []byte(fileHash)})
	})
	mux.HandleFunc("/review", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		userKey, data := parseReq(r)
		if userKey == nil {
			writeRes(w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		var appIdList []string
		appIdListBytes := data["appidlist"]
		status := string(data["status"])
		json.Unmarshal(appIdListBytes, &appIdList)
		reviewStat := make(map[string]string)
		for _, id := range appIdList {
			err := reviewApp(id, userKey, status)
			if err != nil {
				reviewStat[id] = err.Error()
			} else {
				reviewStat[id] = "ok"
			}
		}
		reviewStatBytes, _ := json.Marshal(reviewStat)
		writeRes(w, http.StatusOK, map[string][]byte{"reviewstat": reviewStatBytes})
	})
	mux.HandleFunc("/listvpc", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		userKey, _ := parseReq(r)
		if userKey == nil {
			writeRes(w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		user := parseUserFromKey(userKey)
		vpcRows, err := dbClient.Query("SELECT vpc_id FROM vpc_user WHERE user_key=?", user)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		var vpcList []utils.VpcInfo
		for vpcRows.Next() {
			var vpcId int
			vpcRows.Scan(&vpcId)
			vpcInfoRows := dbClient.QueryRow("SELECT cidr,vpc_name FROM vpc WHERE vpc_id=?", vpcId)
			var cidr, vpcName string
			err := vpcInfoRows.Scan(&cidr, &vpcName)
			if err != nil {
				continue
			}
			vpcList = append(vpcList, utils.VpcInfo{Id: vpcId, Name: vpcName, Cidr: cidr})
		}
		vpcListBytes, _ := json.Marshal(vpcList)
		writeRes(w, http.StatusOK, map[string][]byte{"vpclist": vpcListBytes})
	})
	mux.HandleFunc("/listuser", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		userKey, data := parseReq(r)
		if userKey == nil {
			writeRes(w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		vpcId, _ := strconv.Atoi(string(data["vpcid"]))
		_, permission, err := getUserInfoByKeyAndVpc(vpcId, userKey)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown user.")})
			return
		}
		if !hasAdminPer(permission) {
			writeRes(w, http.StatusForbidden, map[string][]byte{"error": []byte("Permission denied, need admin.")})
			return
		}
		userRows, err := dbClient.Query("SELECT users.user_name,vpc_user.user_key,vpc_user.permission FROM vpc_user INNER JOIN users ON vpc_user.user_key=users.public_key WHERE vpc_user.vpc_id=?", vpcId)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		var userList []utils.UserInfo
		for userRows.Next() {
			var tmpInfo utils.UserInfo
			userRows.Scan(&tmpInfo.Name, &tmpInfo.Key, &tmpInfo.Permission)
			userList = append(userList, tmpInfo)
		}
		userListBytes, _ := json.Marshal(userList)
		writeRes(w, http.StatusOK, map[string][]byte{"userlist": userListBytes})
	})
	mux.HandleFunc("/authuser", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		userKey, data := parseReq(r)
		if userKey == nil {
			writeRes(w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		vpcId, _ := strconv.Atoi(string(data["vpcid"]))
		_, permission, err := getUserInfoByKeyAndVpc(vpcId, userKey)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown user.")})
			return
		}
		if !hasAdminPer(permission) {
			writeRes(w, http.StatusForbidden, map[string][]byte{"error": []byte("Permission denied, need admin.")})
			return
		}
		targetUser := string(data["user"])
		var targetUserName string
		userRows := dbClient.QueryRow("SELECT user_name FROM users WHERE public_key=?", targetUser)
		err = userRows.Scan(&targetUserName)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("User not found.")})
			return
		}
		targetPer, _ := strconv.Atoi(string(data["permission"]))
		_, err = dbClient.Exec("INSERT INTO vpc_user (vpc_id,user_key,permission) VALUES (?,?,?) ON DUPLICATE KEY UPDATE permission=?", vpcId, targetUser, targetPer, targetPer)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		targetInfo := utils.UserInfo{Name: targetUserName, Permission: targetPer, Key: targetUser}
		targetInfoBytes, _ := json.Marshal(targetInfo)
		writeRes(w, http.StatusOK, map[string][]byte{"userinfo": targetInfoBytes})
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
