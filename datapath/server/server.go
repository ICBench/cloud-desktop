package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"datapath/aliutils"
	"datapath/utils"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/coreos/go-systemd/v22/journal"
	_ "github.com/go-sql-driver/mysql"
)

var (
	configPath  = "/usr/local/etc/dataPathServer/config.yaml"
	caPoolPath  = "/usr/local/etc/dataPathServer/CApool"
	crtFilePath = "/usr/local/etc/dataPathServer/cert/server.crt"
	keyFilePath = "/usr/local/etc/dataPathServer/cert/server.key"
	caPool      = x509.NewCertPool()
	dbClient    *sql.DB
	ossBucket   string
)

func loadCerts() {
	err := filepath.Walk(caPoolPath, func(path string, info fs.FileInfo, err error) error {
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
	if err != nil {
		journal.Print(journal.PriErr, "Failed to load certs")
		os.Exit(-1)
	}
}

func connectDb() {
	var err error
	dbClient, err = sql.Open("mysql", "shizhao:icbench@tcp(127.0.0.1:3306)/data_path_server")
	if err != nil {
		journal.Print(journal.PriErr, "Invalid database parameter: %v\n", err)
		os.Exit(-1)
	}
	err = dbClient.Ping()
	if err != nil {
		journal.Print(journal.PriErr, "Failed to connect database: %v\n", err)
		os.Exit(-1)
	}
}

func checkFileExist(client *s3.Client, sendFileList []utils.AppFile) ([]string, error) {
	var needFileList = []string{}
	for _, file := range sendFileList {
		rows, err := dbClient.Query("SELECT hash FROM files WHERE hash = ?", file.Hash)
		if err != nil {
			journal.Print(journal.PriErr, "Failed to query file info from database: %v\n", err)
			return []string{}, err
		}
		if !rows.Next() {
			_, err := client.HeadObject(context.TODO(), &s3.HeadObjectInput{Bucket: aws.String(ossBucket), Key: aws.String(file.Hash)})
			if err != nil {
				var responseError *awshttp.ResponseError
				if errors.As(err, &responseError) && responseError.ResponseError.HTTPStatusCode() == http.StatusNotFound {
					needFileList = append(needFileList, file.Hash)
				} else {
					return []string{}, err
				}
			} else {
				expTime := time.Now().AddDate(0, 30, 0)
				_, err = dbClient.Exec("INSERT INTO files (hash,expiration_time) VALUES (?,?)", file.Hash, expTime)
				if err != nil {
					journal.Print(journal.PriErr, "Failed to insert file info to database: %v\n", err)
					return []string{}, err
				}
			}
		} else {
			err := updateFileInfo(file.Hash)
			if err != nil {
				return []string{}, err
			}
		}
	}
	return needFileList, nil
}

func hasReviewPer(permission int) bool {
	return permission&utils.PerReview != 0
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

func checkSign(dataBytes []byte, userName string, signature []byte) ed25519.PublicKey {
	keyCows, err := dbClient.Query("SELECT public_key FROM users WHERE user_name=?", userName)
	if err != nil {
		return nil
	}
	if keyCows.Next() {
		var keyStr string
		keyCows.Scan(&keyStr)
		pubKeyBytes, _ := hex.DecodeString(keyStr)
		key := ed25519.PublicKey(pubKeyBytes)
		if ed25519.Verify(key, dataBytes, signature) {
			return key
		} else {
			return nil
		}
	} else {
		return nil
	}
}

func getVpcIdByIp(addrStr string) int {
	ipStr, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		return 0
	}
	ipValue := utils.InetAtoN(ipStr)
	vpcRows, err := dbClient.Query("SELECT vpc_id FROM vpc WHERE start_ip_value<? AND end_ip_value>?", ipValue, ipValue)
	if err != nil {
		return -1
	}
	var id int
	if vpcRows.Next() {
		vpcRows.Scan(&id)
	} else {
		id = 0
	}
	return id
}

func getVpcIdByName(vpcName string) (int, error) {
	vpcRows, err := dbClient.Query("SELECT vpc_id FROM vpc WHERE vpc_name=?", vpcName)
	if err != nil {
		return 0, fmt.Errorf("failed to access database")
	}
	var id int
	if vpcRows.Next() {
		vpcRows.Scan(&id)
	} else {
		id = 0
	}
	return id, nil
}

func getVpcNameById(vpcId int) (string, error) {
	vpcRows, err := dbClient.Query("SELECT vpc_name FROM vpc WHERE vpc_id=?", vpcId)
	if err != nil {
		return "", fmt.Errorf("failed to access database")
	}
	var name string
	if vpcRows.Next() {
		vpcRows.Scan(&name)
	} else {
		name = "outside"
	}
	return name, nil
}

func isOutside(vpcId int) bool {
	return vpcId == 0
}

func parseUserFromKey(userKey ed25519.PublicKey) (user string) {
	user = hex.EncodeToString(userKey)
	return
}

func getUserInfoByUserAndVpc(vpcId int, user string) (userName string, permission int, err error) {
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
	user := parseUserFromKey(userKey)
	_, permission, err := getUserInfoByUserAndVpc(dstVpcId, user)
	if err != nil {
		return fmt.Errorf("internal server error: unknown user")
	}
	if !hasReviewPer(permission) {
		return fmt.Errorf("no permission")
	}
	userRows := dbClient.QueryRow("SELECT user_name FROM users WHERE public_key=?", user)
	var userName string
	err = userRows.Scan(&userName)
	if err != nil {
		return fmt.Errorf("failed to query user")
	}
	_, err = dbClient.Exec("UPDATE applications SET approval_status=?,reviewer=? WHERE id=?", status, user, id)
	if err != nil {
		return fmt.Errorf("failed to update database")
	}
	_, err = dbClient.Exec("INSERT INTO review_records (reviewer_name,reviewer_key,approval_status,review_time,application_id) VALUES (?,?,?,?,?)", userName, user, status, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update database")
	}
	return nil
}

func filterAllowedApp(user string, vpcId int, appStrList []string) (allowedAppList, rejectedAppList []int, err error) {
	for _, idStr := range appStrList {
		var id int
		id, err = strconv.Atoi(idStr)
		if err != nil {
			continue
		}
		appRows := dbClient.QueryRow("SELECT owner,destination_vpc_id,approval_status FROM applications WHERE id=?", id)
		var owner string
		var dst int
		var status int
		err = appRows.Scan(&owner, &dst, &status)
		if err != nil {
			return
		}
		if user != owner || vpcId != dst {
			var permission int
			_, permission, err = getUserInfoByUserAndVpc(dst, user)
			if err != nil {
				return
			}
			if !hasReviewPer(permission) {
				rejectedAppList = append(rejectedAppList, id)
				continue
			}
		} else {
			if !isAppStatAllow(status) {
				rejectedAppList = append(rejectedAppList, id)
				continue
			}
		}
		allowedAppList = append(allowedAppList, id)
	}
	return
}

func parseReq(req *http.Request) (userKey ed25519.PublicKey, data map[string][]byte) {
	req.ParseMultipartForm(2 << 30)
	dataBytes, _ := hex.DecodeString(req.PostFormValue("data"))
	signature, _ := hex.DecodeString(req.PostFormValue("signature"))
	userName := req.PostFormValue("username")
	userKey = checkSign(dataBytes, userName, signature)
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
		var warning []string = []string{}
		dstStr := string(data["dstname"])
		src := getVpcIdByIp(r.RemoteAddr)
		if src == -1 {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		if src == 0 {
			warning = append(warning, "Src: choose outside")
		}
		dst, err := getVpcIdByName(dstStr)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		if dst == -1 {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		if dst == 0 {
			warning = append(warning, "Dst: choose outside")
		}
		if dst == src {
			writeRes(w, http.StatusBadRequest, map[string][]byte{"error": []byte("Same src and dst.")})
			return
		}
		var sendFileList []utils.AppFile
		err = json.Unmarshal(data["sendfile"], &sendFileList)
		if err != nil {
			writeRes(w, http.StatusMisdirectedRequest, map[string][]byte{"error": []byte("Error send file list.")})
			return
		}
		cred := aliutils.GetStsCred("", []string{}, ossBucket)
		client := utils.NewOssClient(cred.AccessKeyId, cred.AccessKeySecret, cred.SecurityToken, true)
		needFileList, err := checkFileExist(client, sendFileList)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access file info.")})
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
				warningBytes, _ := json.Marshal(warning)
				writeRes(w, http.StatusOK, map[string][]byte{"warning": warningBytes})
				return
			}
		} else {
			returnBytes, _ := json.Marshal(needFileList)
			var useInStr string
			if !isOutside(src) {
				useInStr = "true"
			} else {
				useInStr = "false"
			}
			cred := aliutils.GetStsCred(aliutils.ActionPutObject, []string{}, ossBucket)
			writeRes(w, http.StatusPreconditionRequired, map[string][]byte{
				"needfile":        returnBytes,
				"accesskeyid":     []byte(cred.AccessKeyId),
				"accesskeysecret": []byte(cred.AccessKeySecret),
				"securitytoken":   []byte(cred.SecurityToken),
				"usein":           []byte(useInStr),
				"ossbucket":       []byte(ossBucket),
			})
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
		if vpcId == -1 {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown VPC.")})
			return
		}
		userName, permission, err := getUserInfoByUserAndVpc(vpcId, parseUserFromKey(userKey))
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown user.")})
			return
		}
		vpcName, err := getVpcNameById(vpcId)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown VPC.")})
			return
		}
		writeRes(w, http.StatusOK, map[string][]byte{
			"vpc":        []byte(vpcName),
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
		if vpcId == -1 {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown VPC.")})
			return
		}
		_, permission, err := getUserInfoByUserAndVpc(vpcId, user)
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
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		var appList []utils.AppInfo
		for appRows.Next() {
			var tmpApp utils.AppInfo
			var srcId, dstId int
			appRows.Scan(&tmpApp.Id, &tmpApp.User, &srcId, &dstId, &tmpApp.Status)
			tmpApp.Src, err = getVpcNameById(srcId)
			if err != nil {
				continue
			}
			tmpApp.Dst, err = getVpcNameById(dstId)
			if err != nil {
				continue
			}
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
			_, permission, err := getUserInfoByUserAndVpc(dst, user)
			if err != nil {
				writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown user.")})
				return
			}
			if !hasReviewPer(permission) {
				writeRes(w, http.StatusForbidden, map[string][]byte{"error": []byte("User have no permission.")})
				return
			}
		}
		appFileRow, err := dbClient.Query("SELECT file_info,file_hash FROM application_file WHERE application_id=?", id)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		var appInfo []utils.AppFile
		for appFileRow.Next() {
			var tmpInfo utils.AppFile
			err := appFileRow.Scan(&tmpInfo.RelPath, &tmpInfo.Hash)
			if err != nil {
				continue
			}
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
		user := parseUserFromKey(userKey)
		vpcId := getVpcIdByIp(r.RemoteAddr)
		if vpcId == -1 {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		var appIdList []string
		json.Unmarshal(data["appidlist"], &appIdList)
		allowedAppList, rejectedAppList, err := filterAllowedApp(user, vpcId, appIdList)
		if err != nil {
			writeRes(w, http.StatusInternalServerError, map[string][]byte{"error": []byte(err.Error())})
			return
		}
		var hashList []string
		var fileList = map[int][]utils.AppFile{}
		for _, appId := range allowedAppList {
			fileList[appId] = []utils.AppFile{}
			appFileRows, err := dbClient.Query("SELECT file_hash,file_info FROM application_file WHERE application_id=?", appId)
			if err != nil {
				continue
			}
			for appFileRows.Next() {
				var tmpInfo utils.AppFile
				appFileRows.Scan(&tmpInfo.Hash, &tmpInfo.RelPath)
				fileList[appId] = append(fileList[appId], tmpInfo)
				hashList = append(hashList, tmpInfo.Hash)
			}
		}
		cred := aliutils.GetStsCred(aliutils.ActionGetObject, hashList, ossBucket)
		var useInStr string
		if !isOutside(vpcId) {
			useInStr = "true"
		} else {
			useInStr = "false"
		}
		allowedAppListBytes, _ := json.Marshal(allowedAppList)
		rejectedAppListBytes, _ := json.Marshal(rejectedAppList)
		fileListBytes, _ := json.Marshal(fileList)
		writeRes(w, http.StatusOK, map[string][]byte{
			"accesskeyid":     []byte(cred.AccessKeyId),
			"accesskeysecret": []byte(cred.AccessKeySecret),
			"securitytoken":   []byte(cred.SecurityToken),
			"usein":           []byte(useInStr),
			"allowedapplist":  allowedAppListBytes,
			"rejectedapplist": rejectedAppListBytes,
			"filelist":        fileListBytes,
			"ossbucket":       []byte(ossBucket),
		})
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
		_, permission, err := getUserInfoByUserAndVpc(vpcId, parseUserFromKey(userKey))
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
			err := userRows.Scan(&tmpInfo.Name, &tmpInfo.Key, &tmpInfo.Permission)
			if err != nil {
				continue
			}
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
		_, permission, err := getUserInfoByUserAndVpc(vpcId, parseUserFromKey(userKey))
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
	cred := aliutils.GetStsCred("", []string{}, ossBucket)
	client := utils.NewOssClient(cred.AccessKeyId, cred.AccessKeySecret, cred.SecurityToken, true)
	for file := range delFileList {
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{Bucket: aws.String(ossBucket), Key: aws.String(file)})
		dbClient.Exec("DELETE FROM files WHERE hash = ?", file)
	}
}

func main() {
	utils.LoadConfig(configPath, map[string]*string{
		"ossbucket": &ossBucket,
	})
	loadCerts()
	connectDb()
	go aliutils.StartStsServer()
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
