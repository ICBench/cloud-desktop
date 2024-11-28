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
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/coreos/go-systemd/v22/journal"
	_ "github.com/go-sql-driver/mysql"
)

const (
	configPath  = "/usr/local/etc/dataPathServer/config.toml"
	caPoolPath  = "/usr/local/etc/dataPathServer/CApool"
	crtFilePath = "/usr/local/etc/dataPathServer/cert/server.crt"
	keyFilePath = "/usr/local/etc/dataPathServer/cert/server.key"
)

var (
	caPool         = x509.NewCertPool()
	dbClient       *sql.DB
	ossBucket      string
	ossInEndPoint  string
	ossOutEndPoint string
	region         string
	sqlSource      string
	pendingApp     sync.Map
)

type pendingAppInfo struct {
	tx         *sql.Tx
	expiryTime time.Time
}

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
		os.Exit(1)
	}
}

func connectDb() {
	var err error
	dbClient, err = sql.Open("mysql", sqlSource)
	if err != nil {
		journal.Print(journal.PriErr, "Invalid database parameter: %v\n", err)
		os.Exit(1)
	}
	_, err = utils.DbOpWithRetry(dbClient, "Ping", "")
	if err != nil {
		journal.Print(journal.PriErr, "Failed to connect database: %v\n", err)
		os.Exit(1)
	}
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

func createNewApplication(tx *sql.Tx, userKey ed25519.PublicKey, srcVpcId int, dstVpcId int, sendFileList []utils.AppFile, status int) (int, error) {
	expTime := time.Now().AddDate(0, 30, 0)
	user := parseUserFromKey(userKey)
	ifce, err := utils.DbOpWithRetry(tx, "Exec", "INSERT INTO applications (owner,source_vpc_id,destination_vpc_id,approval_status,expiry_time) VALUES (?,?,?,?,?)", user, srcVpcId, dstVpcId, status, expTime)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to create new application: %v", err)
		return 0, err
	}
	result := ifce.(sql.Result)
	id, err := result.LastInsertId()
	if err != nil {
		journal.Print(journal.PriErr, "Failed to get application id: %v", err)
		return 0, err
	}
	for _, sendFile := range sendFileList {
		_, err = utils.DbOpWithRetry(tx, "Exec", "INSERT INTO application_file (file_hash,application_id,file_info) VALUES (?,?,?)", sendFile.Hash, id, sendFile.RelPath)
		if err != nil {
			journal.Print(journal.PriErr, "Failed to create new application: %v", err)
			return 0, err
		}
	}
	return int(id), nil
}

func checkSign(dataBytes []byte, userName string, signature []byte) ed25519.PublicKey {
	ifce, err := utils.DbOpWithRetry(dbClient, "Query", "SELECT public_key FROM users WHERE user_name=?", userName)
	if err != nil {
		return nil
	}
	keyCows := ifce.(*sql.Rows)
	defer keyCows.Close()
	if keyCows.Next() {
		var keyStr string
		keyCows.Scan(&keyStr)
		pubKeyBytes, err := hex.DecodeString(keyStr)
		if err != nil {
			journal.Print(journal.PriErr, "Database value error")
			return nil
		}
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
	ifce, err := utils.DbOpWithRetry(dbClient, "Query", "SELECT vpc_id FROM vpc WHERE start_ip_value<? AND end_ip_value>?", ipValue, ipValue)
	if err != nil {
		return -1
	}
	vpcRows := ifce.(*sql.Rows)
	defer vpcRows.Close()
	var id int
	if vpcRows.Next() {
		vpcRows.Scan(&id)
	} else {
		id = 0
	}
	return id
}

func getVpcIdByName(vpcName string) (int, error) {
	ifce, err := utils.DbOpWithRetry(dbClient, "Query", "SELECT vpc_id FROM vpc WHERE vpc_name=?", vpcName)
	if err != nil {
		return 0, fmt.Errorf("failed to access database")
	}
	vpcRows := ifce.(*sql.Rows)
	defer vpcRows.Close()
	var id int
	if vpcRows.Next() {
		vpcRows.Scan(&id)
	} else {
		id = 0
	}
	return id, nil
}

func getVpcInfoById(vpcId int) (vpcName string, cidr string, err error) {
	ifce, err := utils.DbOpWithRetry(dbClient, "Query", "SELECT vpc_name,cidr FROM vpc WHERE vpc_id=?", vpcId)
	if err != nil {
		return
	}
	vpcRows := ifce.(*sql.Rows)
	defer vpcRows.Close()
	if vpcRows.Next() {
		vpcRows.Scan(&vpcName, &cidr)
	} else {
		vpcName = "outside"
		cidr = "0.0.0.0/32"
	}
	err = nil
	return
}

func isOutside(vpcId int) bool {
	return vpcId == 0
}

func parseUserFromKey(userKey ed25519.PublicKey) (user string) {
	user = hex.EncodeToString(userKey)
	return
}

func getUserInfoByUserAndVpc(vpcId int, user string) (userName string, permission int, err error) {
	ifce, err := utils.DbOpWithRetry(dbClient, "Query", "SELECT user_name FROM users WHERE public_key = ?", user)
	if err != nil {
		return
	}
	userRows := ifce.(*sql.Rows)
	defer userRows.Close()
	if !userRows.Next() {
		err = fmt.Errorf("user not exist")
		return
	}
	userRows.Scan(&userName)
	ifce, err = utils.DbOpWithRetry(dbClient, "Query", "SELECT permission FROM vpc_user WHERE user_key = ? AND vpc_id = ?", user, vpcId)
	if err != nil {
		return
	}
	perRows := ifce.(*sql.Rows)
	defer perRows.Close()
	if perRows.Next() {
		perRows.Scan(&permission)
	} else {
		permission = 0
	}
	return
}

func reviewApp(tx *sql.Tx, idStr string, userKey ed25519.PublicKey, statusStr string) error {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return err
	}
	status, err := strconv.Atoi(statusStr)
	if err != nil {
		return err
	}
	ifce, err := utils.DbOpWithRetry(dbClient, "Query", "SELECT destination_vpc_id FROM applications WHERE id=?", id)
	if err != nil {
		return fmt.Errorf("no application %v", idStr)
	}
	appRows := ifce.(*sql.Rows)
	defer appRows.Close()
	var dstVpcId int
	if appRows.Next() {
		appRows.Scan(&dstVpcId)
	} else {
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
	userName, _, err := getUserInfoByUserAndVpc(0, user)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	_, err = utils.DbOpWithRetry(tx, "Exec", "UPDATE applications SET approval_status=? WHERE id=?", status, id)
	if err != nil {
		return fmt.Errorf("failed to update database")
	}
	_, err = utils.DbOpWithRetry(tx, "Exec", "INSERT INTO review_records (reviewer_name,reviewer_key,approval_status,review_time,application_id) VALUES (?,?,?,?,?)", userName, user, status, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update database")
	}
	return nil
}

func filterAllowedApp(user string, vpcId int, appStrList []string) (allowedAppList, rejectedAppList []string, err error) {
	for _, idStr := range appStrList {
		var id int
		id, err = strconv.Atoi(idStr)
		if err != nil {
			continue
		}
		var ifce interface{}
		ifce, err = utils.DbOpWithRetry(dbClient, "Query", "SELECT owner,destination_vpc_id,approval_status FROM applications WHERE id=?", id)
		if err != nil {
			return
		}
		appRows := ifce.(*sql.Rows)
		defer appRows.Close()
		var owner string
		var dst int
		var status int
		if appRows.Next() {
			appRows.Scan(&owner, &dst, &status)
		} else {
			err = fmt.Errorf("invalid application id")
			return
		}
		if user != owner || vpcId != dst {
			var permission int
			_, permission, err = getUserInfoByUserAndVpc(dst, user)
			if err != nil {
				return
			}
			if !hasReviewPer(permission) {
				rejectedAppList = append(rejectedAppList, strconv.Itoa(id))
				continue
			}
		} else {
			if !isAppStatAllow(status) {
				rejectedAppList = append(rejectedAppList, strconv.Itoa(id))
				continue
			}
		}
		allowedAppList = append(allowedAppList, strconv.Itoa(id))
	}
	return
}

func parseReq(req *http.Request) (ed25519.PublicKey, map[string][]byte) {
	req.ParseMultipartForm(2 << 30)
	dataBytes, err := hex.DecodeString(req.PostFormValue("data"))
	if err != nil {
		return nil, nil
	}
	signature, err := hex.DecodeString(req.PostFormValue("signature"))
	if err != nil {
		return nil, nil
	}
	userName := req.PostFormValue("username")
	userKey := checkSign(dataBytes, userName, signature)
	if userKey == nil {
		return nil, nil
	}
	jsonData := make(map[string]string)
	data := make(map[string][]byte)
	err = json.Unmarshal(dataBytes, &jsonData)
	if err != nil {
		return nil, nil
	}
	for fieldName, fieldValue := range jsonData {
		data[fieldName], err = hex.DecodeString(fieldValue)
		if err != nil {
			continue
		}
	}
	return userKey, data
}

func writeRes(tx *sql.Tx, res http.ResponseWriter, statusCode int, data map[string][]byte) {
	if tx != nil {
		if statusCode == http.StatusOK {
			utils.DbOpWithRetry(tx, "Commit", "")
		} else {
			utils.DbOpWithRetry(tx, "Rollback", "")
		}
	}
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
			writeRes(nil, w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		ifce, err := utils.DbOpWithRetry(dbClient, "Begin", "")
		if err != nil {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		tx := ifce.(*sql.Tx)
		userKey, data := parseReq(r)
		if userKey == nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		var warning []string = []string{}
		dstStr := string(data["dstname"])
		src := getVpcIdByIp(r.RemoteAddr)
		if src == -1 {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		if src == 0 {
			warning = append(warning, "Src: choose outside")
		}
		dst, err := getVpcIdByName(dstStr)
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		if dst == -1 {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		if dst == 0 {
			warning = append(warning, "Dst: choose outside")
		}
		if dst == src {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Same src and dst.")})
			return
		}
		var sendFileList []utils.AppFile
		err = json.Unmarshal(data["sendfile"], &sendFileList)
		if err != nil {
			writeRes(tx, w, http.StatusMisdirectedRequest, map[string][]byte{"error": []byte("Error send file list.")})
			return
		}
		ifce, err = utils.DbOpWithRetry(dbClient, "Begin", "")
		if err != nil {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		appTx := ifce.(*sql.Tx)
		appId, err := createNewApplication(appTx, userKey, src, dst, sendFileList, 2)
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Create application error.")})
			return
		}
		var endPoint string
		if !isOutside(src) {
			endPoint = ossInEndPoint
		} else {
			endPoint = ossOutEndPoint
		}
		cred := aliutils.GetStsCred(aliutils.ActionPutObject, []string{}, ossBucket)
		if cred.Err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Sts server error.")})
			return
		}
		warningBytes, _ := json.Marshal(warning)
		pendingApp.Store(appId, pendingAppInfo{tx: appTx, expiryTime: time.Now().Add(24 * time.Hour)})
		writeRes(tx, w, http.StatusOK, map[string][]byte{
			"accesskeyid":     []byte(cred.AccessKeyId),
			"accesskeysecret": []byte(cred.AccessKeySecret),
			"securitytoken":   []byte(cred.SecurityToken),
			"endpoint":        []byte(endPoint),
			"region":          []byte(region),
			"ossbucket":       []byte(ossBucket),
			"appid":           []byte(strconv.Itoa(appId)),
			"warning":         warningBytes,
		})
	})
	mux.HandleFunc("/complete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(nil, w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		ifce, err := utils.DbOpWithRetry(dbClient, "Begin", "")
		if err != nil {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		tx := ifce.(*sql.Tx)
		userKey, data := parseReq(r)
		if userKey == nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		appId, _ := strconv.Atoi(string(data["appid"]))
		ifce, exist := pendingApp.Load(appId)
		if !exist {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Application does not exist.")})
			return
		}
		info := ifce.(pendingAppInfo)
		ifce, err = utils.DbOpWithRetry(dbClient, "Query", "SELECT file_hash FROM application_file WHERE application_id=?", appId)
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		appFileRows := ifce.(*sql.Rows)
		defer appFileRows.Close()
		cred := aliutils.GetStsCred("", []string{}, ossBucket)
		if cred.Err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Sts server error.")})
			return
		}
		ossClient, err := utils.NewOssClient(cred.AccessKeyId, cred.AccessKeySecret, cred.SecurityToken, ossInEndPoint, region)
		if err != nil {
			journal.Print(journal.PriErr, "Failed to create oss client %v", err)
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access oss server.")})
			return
		}
		for appFileRows.Next() {
			var hash string
			err := appFileRows.Scan(&hash)
			if err != nil {
				writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
				return
			}
			_, err = ossClient.HeadObject(context.TODO(), &s3.HeadObjectInput{
				Bucket: aws.String(ossBucket),
				Key:    aws.String(strconv.Itoa(appId) + "/" + hash),
			})
			if err != nil {
				var responseError *awshttp.ResponseError
				if errors.As(err, &responseError) && responseError.ResponseError.HTTPStatusCode() == http.StatusNotFound {
					writeRes(tx, w, http.StatusPreconditionFailed, map[string][]byte{"error": []byte("Some files not exist.")})
					return
				} else {
					writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access oss server.")})
					return
				}
			}
		}
		ifce, err = utils.DbOpWithRetry(info.tx, "Query", "SELECT source_vpc_id FROM applications WHERE id=?", appId)
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		appRows := ifce.(*sql.Rows)
		defer appRows.Close()
		var src int
		if appRows.Next() {
			appRows.Scan(&src)
		} else {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Application not found")})
			return
		}
		appRows.Close()
		var iniStat int
		if isOutside(src) {
			iniStat = 0
		} else {
			iniStat = 1
		}
		_, err = utils.DbOpWithRetry(info.tx, "Exec", "UPDATE applications SET approval_status=? WHERE id=?", iniStat, appId)
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		_, err = utils.DbOpWithRetry(info.tx, "Commit", "")
		if err != nil {
			journal.Print(journal.PriErr, "Database transaction %v commit Failed.", appId)
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		writeRes(tx, w, http.StatusOK, map[string][]byte{})
	})
	mux.HandleFunc("/cancel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(nil, w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		ifce, err := utils.DbOpWithRetry(dbClient, "Begin", "")
		if err != nil {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		tx := ifce.(*sql.Tx)
		userKey, data := parseReq(r)
		if userKey == nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		appId, _ := strconv.Atoi(string(data["appid"]))
		ifce, exist := pendingApp.LoadAndDelete(appId)
		if !exist {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Application does not exist.")})
			return
		}
		info := ifce.(pendingAppInfo)
		_, err = utils.DbOpWithRetry(info.tx, "Rollback", "")
		if err != nil {
			journal.Print(journal.PriErr, "Application %v rollback failed.", appId)
		}
		writeRes(tx, w, http.StatusOK, map[string][]byte{})
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
			writeRes(nil, w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		ifce, err := utils.DbOpWithRetry(dbClient, "Begin", "")
		if err != nil {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		tx := ifce.(*sql.Tx)
		userKey, _ := parseReq(r)
		if userKey == nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		vpcId := getVpcIdByIp(r.RemoteAddr)
		if vpcId == -1 {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown VPC.")})
			return
		}
		userName, permission, err := getUserInfoByUserAndVpc(vpcId, parseUserFromKey(userKey))
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown user.")})
			return
		}
		vpcName, _, err := getVpcInfoById(vpcId)
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown VPC.")})
			return
		}
		writeRes(tx, w, http.StatusOK, map[string][]byte{
			"vpc":        []byte(vpcName),
			"username":   []byte(userName),
			"permission": []byte(strconv.Itoa(permission)),
		})
	})
	mux.HandleFunc("/applist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(nil, w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		ifce, err := utils.DbOpWithRetry(dbClient, "Begin", "")
		if err != nil {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		tx := ifce.(*sql.Tx)
		userKey, _ := parseReq(r)
		if userKey == nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		user := parseUserFromKey(userKey)
		ifce, err = utils.DbOpWithRetry(dbClient, "Query", "SELECT vpc_id,permission FROM vpc_user WHERE user_key=?", user)
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		perRows := ifce.(*sql.Rows)
		defer perRows.Close()
		var appList []utils.AppInfo
		for perRows.Next() {
			var vpcId, permission int
			err := perRows.Scan(&vpcId, &permission)
			if err != nil {
				writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
				return
			}
			var appRows *sql.Rows
			if hasReviewPer(permission) {
				ifce, err = utils.DbOpWithRetry(dbClient, "Query", "SELECT applications.id,users.user_name,applications.source_vpc_id,applications.destination_vpc_id,applications.approval_status FROM applications INNER JOIN users ON applications.owner=users.public_key WHERE applications.source_vpc_id=?", vpcId)
			} else {
				ifce, err = utils.DbOpWithRetry(dbClient, "Query", "SELECT applications.id,users.user_name,applications.source_vpc_id,applications.destination_vpc_id,applications.approval_status FROM applications INNER JOIN users ON applications.owner=users.public_key WHERE applications.source_vpc_id=? AND applications.owner=?", vpcId, user)
			}
			if err != nil {
				journal.Print(journal.PriErr, "Failed to query application info from database: %v\n", err)
				writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
				return
			}
			appRows = ifce.(*sql.Rows)
			defer appRows.Close()
			for appRows.Next() {
				var tmpApp utils.AppInfo
				var srcId, dstId int
				appRows.Scan(&tmpApp.Id, &tmpApp.User, &srcId, &dstId, &tmpApp.Status)
				tmpApp.Src, _, err = getVpcInfoById(srcId)
				if err != nil {
					continue
				}
				tmpApp.Dst, _, err = getVpcInfoById(dstId)
				if err != nil {
					continue
				}
				appList = append(appList, tmpApp)
			}
		}
		appListBytes, _ := json.Marshal(appList)
		writeRes(tx, w, http.StatusOK, map[string][]byte{"applist": appListBytes})
	})
	mux.HandleFunc("/appinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(nil, w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		ifce, err := utils.DbOpWithRetry(dbClient, "Begin", "")
		if err != nil {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		tx := ifce.(*sql.Tx)
		userKey, data := parseReq(r)
		if userKey == nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		idStr := string(data["id"])
		id, err := strconv.Atoi(idStr)
		if err != nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Invalid application id.")})
			return
		}
		user := parseUserFromKey(userKey)
		ifce, err = utils.DbOpWithRetry(dbClient, "Query", "SELECT owner,destination_vpc_id FROM applications WHERE id=?", id)
		if err != nil {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		appRows := ifce.(*sql.Rows)
		defer appRows.Close()
		var owner string
		var dst int
		if appRows.Next() {
			appRows.Scan(&owner, &dst)
		} else {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Application not found")})
			return
		}
		if user != owner {
			_, permission, err := getUserInfoByUserAndVpc(dst, user)
			if err != nil {
				writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown user.")})
				return
			}
			if !hasReviewPer(permission) {
				writeRes(tx, w, http.StatusForbidden, map[string][]byte{"error": []byte("User have no permission.")})
				return
			}
		}
		ifce, err = utils.DbOpWithRetry(dbClient, "Query", "SELECT file_info,file_hash FROM application_file WHERE application_id=?", id)
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		appFileRows := ifce.(*sql.Rows)
		defer appFileRows.Close()
		var appInfo []utils.AppFile
		for appFileRows.Next() {
			var tmpInfo utils.AppFile
			err := appFileRows.Scan(&tmpInfo.RelPath, &tmpInfo.Hash)
			if err != nil {
				continue
			}
			appInfo = append(appInfo, tmpInfo)
		}
		appInfoBytes, _ := json.Marshal(appInfo)
		writeRes(tx, w, http.StatusOK, map[string][]byte{"appinfo": appInfoBytes})
	})
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(nil, w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		ifce, err := utils.DbOpWithRetry(dbClient, "Begin", "")
		if err != nil {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		tx := ifce.(*sql.Tx)
		userKey, data := parseReq(r)
		if userKey == nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		user := parseUserFromKey(userKey)
		vpcId := getVpcIdByIp(r.RemoteAddr)
		if vpcId == -1 {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		var appIdList []string
		err = json.Unmarshal(data["appidlist"], &appIdList)
		if err != nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Invalid application list.")})
			return
		}
		allowedAppList, rejectedAppList, err := filterAllowedApp(user, vpcId, appIdList)
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte(err.Error())})
			return
		}
		var fileList = map[string][]utils.AppFile{}
		for _, appId := range allowedAppList {
			fileList[appId] = []utils.AppFile{}
			ifce, err = utils.DbOpWithRetry(dbClient, "Query", "SELECT file_hash,file_info FROM application_file WHERE application_id=?", appId)
			if err != nil {
				continue
			}
			appFileRows := ifce.(*sql.Rows)
			defer appFileRows.Close()
			for appFileRows.Next() {
				var tmpInfo utils.AppFile
				appFileRows.Scan(&tmpInfo.Hash, &tmpInfo.RelPath)
				fileList[appId] = append(fileList[appId], tmpInfo)
			}
		}
		cred := aliutils.GetStsCred(aliutils.ActionGetObject, allowedAppList, ossBucket)
		if cred.Err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Sts server error.")})
			return
		}
		var endPoint string
		if !isOutside(vpcId) {
			endPoint = ossInEndPoint
		} else {
			endPoint = ossOutEndPoint
		}
		allowedAppListBytes, _ := json.Marshal(allowedAppList)
		rejectedAppListBytes, _ := json.Marshal(rejectedAppList)
		fileListBytes, _ := json.Marshal(fileList)
		writeRes(tx, w, http.StatusOK, map[string][]byte{
			"accesskeyid":     []byte(cred.AccessKeyId),
			"accesskeysecret": []byte(cred.AccessKeySecret),
			"securitytoken":   []byte(cred.SecurityToken),
			"endpoint":        []byte(endPoint),
			"region":          []byte(region),
			"allowedapplist":  allowedAppListBytes,
			"rejectedapplist": rejectedAppListBytes,
			"filelist":        fileListBytes,
			"ossbucket":       []byte(ossBucket),
		})
	})
	mux.HandleFunc("/review", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(nil, w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		ifce, err := utils.DbOpWithRetry(dbClient, "Begin", "")
		if err != nil {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		tx := ifce.(*sql.Tx)
		userKey, data := parseReq(r)
		if userKey == nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		var appIdList []string
		appIdListBytes := data["appidlist"]
		status := string(data["status"])
		err = json.Unmarshal(appIdListBytes, &appIdList)
		if err != nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Invalid application list.")})
			return
		}
		reviewStat := make(map[string]string)
		for _, id := range appIdList {
			err := reviewApp(tx, id, userKey, status)
			if err != nil {
				reviewStat[id] = err.Error()
			} else {
				reviewStat[id] = "ok"
			}
		}
		reviewStatBytes, _ := json.Marshal(reviewStat)
		writeRes(tx, w, http.StatusOK, map[string][]byte{"reviewstat": reviewStatBytes})
	})
	mux.HandleFunc("/listvpc", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(nil, w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		ifce, err := utils.DbOpWithRetry(dbClient, "Begin", "")
		if err != nil {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		tx := ifce.(*sql.Tx)
		userKey, _ := parseReq(r)
		if userKey == nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		user := parseUserFromKey(userKey)
		ifce, err = utils.DbOpWithRetry(dbClient, "Query", "SELECT vpc_id FROM vpc_user WHERE user_key=?", user)
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		vpcRows := ifce.(*sql.Rows)
		defer vpcRows.Close()
		var vpcList []utils.VpcInfo
		for vpcRows.Next() {
			var vpcId int
			vpcRows.Scan(&vpcId)
			vpcName, cidr, err := getVpcInfoById(vpcId)
			if err != nil {
				writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
				return
			}
			vpcList = append(vpcList, utils.VpcInfo{Id: vpcId, Name: vpcName, Cidr: cidr})
		}
		vpcListBytes, _ := json.Marshal(vpcList)
		writeRes(tx, w, http.StatusOK, map[string][]byte{"vpclist": vpcListBytes})
	})
	mux.HandleFunc("/listuser", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(nil, w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		ifce, err := utils.DbOpWithRetry(dbClient, "Begin", "")
		if err != nil {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		tx := ifce.(*sql.Tx)
		userKey, data := parseReq(r)
		if userKey == nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		vpcId, err := strconv.Atoi(string(data["vpcid"]))
		if err != nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Invalid VPC id.")})
			return
		}
		_, permission, err := getUserInfoByUserAndVpc(vpcId, parseUserFromKey(userKey))
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown user.")})
			return
		}
		if !hasAdminPer(permission) {
			writeRes(tx, w, http.StatusForbidden, map[string][]byte{"error": []byte("Permission denied, need admin.")})
			return
		}
		ifce, err = utils.DbOpWithRetry(dbClient, "Query", "SELECT users.user_name,vpc_user.user_key,vpc_user.permission FROM vpc_user INNER JOIN users ON vpc_user.user_key=users.public_key WHERE vpc_user.vpc_id=?", vpcId)
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		userRows := ifce.(*sql.Rows)
		defer userRows.Close()
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
		writeRes(tx, w, http.StatusOK, map[string][]byte{"userlist": userListBytes})
	})
	mux.HandleFunc("/authuser", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeRes(nil, w, http.StatusMethodNotAllowed, map[string][]byte{"error": []byte("Only post method allowed.")})
			return
		}
		ifce, err := utils.DbOpWithRetry(dbClient, "Begin", "")
		if err != nil {
			writeRes(nil, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Database error")})
			return
		}
		tx := ifce.(*sql.Tx)
		userKey, data := parseReq(r)
		if userKey == nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Unknown user signature.")})
			return
		}
		vpcId, err := strconv.Atoi(string(data["vpcid"]))
		if err != nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Invalid VPC id.")})
			return
		}
		_, permission, err := getUserInfoByUserAndVpc(vpcId, parseUserFromKey(userKey))
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Unknown user.")})
			return
		}
		if !hasAdminPer(permission) {
			writeRes(tx, w, http.StatusForbidden, map[string][]byte{"error": []byte("Permission denied, need admin.")})
			return
		}
		targetUser := string(data["user"])
		var targetUserName string
		targetUserName, _, err = getUserInfoByUserAndVpc(0, targetUser)
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("User not found.")})
			return
		}
		targetPer, err := strconv.Atoi(string(data["permission"]))
		if err != nil {
			writeRes(tx, w, http.StatusBadRequest, map[string][]byte{"error": []byte("Invalid permission setting.")})
			return
		}
		_, err = utils.DbOpWithRetry(tx, "Exec", "INSERT INTO vpc_user (vpc_id,user_key,permission) VALUES (?,?,?) ON DUPLICATE KEY UPDATE permission=?", vpcId, targetUser, targetPer, targetPer)
		if err != nil {
			writeRes(tx, w, http.StatusInternalServerError, map[string][]byte{"error": []byte("Failed to access database.")})
			return
		}
		targetInfo := utils.UserInfo{Name: targetUserName, Permission: targetPer, Key: targetUser}
		targetInfoBytes, _ := json.Marshal(targetInfo)
		writeRes(tx, w, http.StatusOK, map[string][]byte{"userinfo": targetInfoBytes})
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

func deleteOssFile(idList []int) (failedIdList []int) {
	cred := aliutils.GetStsCred("", []string{}, ossBucket)
	if cred.Err != nil {
		journal.Print(journal.PriErr, "File tidy error: sts server error.")
		return idList
	}
	ossClient, err := utils.NewOssClient(cred.AccessKeyId, cred.AccessKeySecret, cred.SecurityToken, ossInEndPoint, region)
	if err != nil {
		journal.Print(journal.PriErr, "File tidy error: failed to create oss client %v", err)
		return idList
	}
	for _, id := range idList {
		for {
			res, err := ossClient.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
				Bucket: aws.String(ossBucket),
				Prefix: aws.String(strconv.Itoa(id) + "/"),
			})
			if err != nil {
				failedIdList = append(failedIdList, id)
				break
			}
			var objs []types.ObjectIdentifier
			for _, obj := range res.Contents {
				objs = append(objs, types.ObjectIdentifier{
					Key: obj.Key,
				})
			}
			_, err = ossClient.DeleteObjects(context.Background(), &s3.DeleteObjectsInput{
				Bucket: aws.String(ossBucket),
				Delete: &types.Delete{
					Objects: objs,
				},
			})
			if err != nil {
				failedIdList = append(failedIdList, id)
				break
			}
			isTruncated := aws.ToBool(res.IsTruncated)
			if !isTruncated {
				break
			}
		}
	}
	return
}

func fileTidy(failedIdList []int) []int {
	ifce, err := utils.DbOpWithRetry(dbClient, "Begin", "")
	if err != nil {
		journal.Print(journal.PriErr, "Error while trying to tidy files: %v\n", err)
		return failedIdList
	}
	tx := ifce.(*sql.Tx)
	ifce, err = utils.DbOpWithRetry(dbClient, "Query", "SELECT id FROM applications WHERE approval_status=2")
	if err != nil {
		journal.Print(journal.PriErr, "Error while trying to tidy files: %v\n", err)
		return failedIdList
	}
	pendingAppRow := ifce.(*sql.Rows)
	defer pendingAppRow.Close()
	for pendingAppRow.Next() {
		var id int
		pendingAppRow.Scan(&id)
		failedIdList = append(failedIdList, id)
		ifce, exist := pendingApp.Load(id)
		if !exist {
			_, err := utils.DbOpWithRetry(tx, "Exec", "DELETE FROM applications WHERE id = ?", id)
			if err != nil {
				journal.Print(journal.PriErr, "File tidy error: failed to access database.")
			}
			continue
		}
		info := ifce.(pendingAppInfo)
		if info.expiryTime.Before(time.Now()) {
			_, err := utils.DbOpWithRetry(info.tx, "Rollback", "")
			if err != nil {
				journal.Print(journal.PriErr, "Failed to rollback application %v: %v", id, err)
				continue
			}
			pendingApp.Delete(id)
		}
	}
	ifce, err = utils.DbOpWithRetry(dbClient, "Query", "SELECT id FROM applications WHERE expiry_time < ?", time.Now())
	if err != nil {
		journal.Print(journal.PriErr, "Error while trying to tidy files: %v\n", err)
		return failedIdList
	}
	outdatedAppRows := ifce.(*sql.Rows)
	for outdatedAppRows.Next() {
		var id int
		outdatedAppRows.Scan(&id)
		failedIdList = append(failedIdList, id)
	}
	_, err = utils.DbOpWithRetry(tx, "Exec", "DELETE FROM applications WHERE expiry_time < ?", time.Now())
	if err != nil {
		journal.Print(journal.PriErr, "File tidy error: failed to access database.")
	}
	failedIdList = deleteOssFile(failedIdList)
	utils.DbOpWithRetry(tx, "Commit", "")
	return failedIdList
}

func main() {
	utils.LoadConfig(configPath, map[string]*string{
		"ossbucket":      &ossBucket,
		"ossinendpoint":  &ossInEndPoint,
		"ossoutendpoint": &ossOutEndPoint,
		"region":         &region,
		"sqlsource":      &sqlSource,
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
	var tidyIdList = []int{}
	for {
		tidyIdList = fileTidy(tidyIdList)
		time.Sleep(24 * time.Hour)
	}
}
