package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/spf13/cobra"
)

var (
	serverHost    = "106.15.236.65"
	caPoolPath    = "/usr/local/etc/dataPathClient/CApool"
	caPool        = x509.NewCertPool()
	crtFilePath   = "/usr/local/etc/dataPathClient/certs/client.crt"
	keyFilePath   = "/usr/local/etc/dataPathClient/certs/client.key"
	client        *http.Client
	loPrivKeyPath = "/usr/local/etc/dataPathClient/privKey"
	loPrivKey     ed25519.PrivateKey
)

func loadCertsAndKeys() {
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

func loadHttpClient() {
	cert, err := tls.LoadX509KeyPair(crtFilePath, keyFilePath)
	if err != nil {
		log.Println("Failed to load certs")
	}
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{cert},
			},
			DialContext: (&net.Dialer{
				LocalAddr: &net.TCPAddr{
					Port: 9993,
				},
			}).DialContext,
		},
	}
}

func sendReq(host string, data map[string][]byte) *http.Response {
	var buf bytes.Buffer
	bufWriter := multipart.NewWriter(&buf)
	jsonData := make(map[string]string)
	for fieldName, fieldValue := range data {
		jsonData[fieldName] = hex.EncodeToString(fieldValue)
	}
	saltData := make([]byte, 512)
	rand.Read(saltData)
	jsonData["salt"] = hex.EncodeToString(saltData)
	jsonBytes, _ := json.Marshal(jsonData)
	signature := ed25519.Sign(loPrivKey, jsonBytes)
	bufWriter.WriteField("data", hex.EncodeToString(jsonBytes))
	bufWriter.WriteField("signature", hex.EncodeToString(signature))
	bufWriter.Close()
	req, _ := http.NewRequest("POST", host, &buf)
	req.Header.Set("Content-Type", bufWriter.FormDataContentType())
	res, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send request: %v\n", err)
		os.Exit(-1)
	}
	return res
}

func parseRes(res *http.Response) (data map[string][]byte) {
	data = map[string][]byte{}
	jsonData := make(map[string]string)
	jsonBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("Failed to parse response: %v\n", err)
		os.Exit(-1)
	}
	json.Unmarshal(jsonBytes, &jsonData)
	for fieldName, fieldValue := range jsonData {
		data[fieldName], _ = hex.DecodeString(fieldValue)
	}
	return
}

func queryUserInfo() map[string]string {
	host := fmt.Sprintf("https://%v:9991/self", serverHost)
	res := sendReq(host, make(map[string][]byte))
	if res.StatusCode != http.StatusOK {
		log.Printf("Send request failed http: %v\n", res.StatusCode)
		os.Exit(-1)
	}
	data := parseRes(res)
	return map[string]string{
		"username":   string(data["username"]),
		"permission": string(data["permission"]),
		"vpc":        string(data["vpc"]),
	}
}

type appRow struct {
	Id       int
	User     string
	Status   int8
	Src, Dst string
}

func queryAppList() (appList []appRow) {
	host := fmt.Sprintf("https://%v:9991/applist", serverHost)
	res := sendReq(host, map[string][]byte{})
	if res.StatusCode != http.StatusOK {
		log.Printf("Send request failed http: %v\n", res.StatusCode)
		os.Exit(-1)
	}
	data := parseRes(res)
	json.Unmarshal(data["applist"], &appList)
	return
}

type appFile struct {
	Hash    string
	RelPath string
}

func queryOneAppInfo(id int) (appInfo []appFile, err error) {
	host := fmt.Sprintf("https://%v:9991/appinfo", serverHost)
	fmt.Println(string([]byte(strconv.Itoa(id))))
	res := sendReq(host, map[string][]byte{"id": []byte(strconv.Itoa(id))})
	if res.StatusCode != http.StatusOK {
		log.Printf("Send request failed http: %v\n", res.StatusCode)
		return
	}
	data := parseRes(res)
	json.Unmarshal(data["appinfo"], &appInfo)
	sort.Slice(appInfo, func(i, j int) bool {
		return appInfo[i].RelPath < appInfo[j].RelPath
	})
	return
}

func queryAppInfo(idList []int) (appInfo map[int][]appFile) {
	appInfo = make(map[int][]appFile)
	for _, id := range idList {
		tmpInfo, err := queryOneAppInfo(id)
		if err != nil {
			log.Printf("Failed to get application %v info\n", id)
			continue
		}
		appInfo[id] = tmpInfo
	}
	return
}

func downloadFile(fileHash string, appId string, file *os.File) {
	host := fmt.Sprintf("https://%v:9991/download", serverHost)
	var sendData = map[string][]byte{
		"hash":  []byte(fileHash),
		"appid": []byte(appId),
	}
	res := sendReq(host, sendData)
	if res.StatusCode != http.StatusOK {
		log.Printf("Query failed http: %v\n", res.StatusCode)
		return
	}
	recData := parseRes(res)
	if string(recData["hash"]) == fileHash {
		file.Write(recData["file"])
	} else {
		log.Printf("Unmatched file received")
	}
}

func downloadFiles(idList []int, basePath string) {
	appInfo := queryAppInfo(idList)
	for id, app := range appInfo {
		appSavePath := basePath + strconv.Itoa(id) + "/"
		err := os.MkdirAll(appSavePath, 0755)
		if err != nil {
			log.Printf("Failed to access %v: %v", appSavePath, err)
			os.Exit(-1)
		}
		for _, info := range app {
			fileSavePath := appSavePath + info.RelPath
			err := os.MkdirAll(filepath.Dir(fileSavePath), 0755)
			if err != nil {
				log.Printf("Failed to access %v: %v", fileSavePath, err)
				os.Exit(-1)
			}
			file, err := os.Create(fileSavePath)
			if err != nil {
				log.Printf("Failed to access %v: %v", fileSavePath, err)
				os.Exit(-1)
			}
			defer file.Close()
			downloadFile(info.Hash, strconv.Itoa(id), file)
		}
	}
}

func startGUI() {

}

func main() {
	loadCertsAndKeys()
	loadHttpClient()
	var jsonFlag bool
	var rootCmd = &cobra.Command{
		Use:   "outbox",
		Short: "Connect to server for get files, manage and review",
		Args:  cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			startGUI()
		},
	}
	rootCmd.PersistentFlags().BoolVarP(&jsonFlag, "json", "j", false, "Use this flag to specify the json format output, GUI will ignore this flag")
	var cmdInfo = &cobra.Command{
		Use:   "info",
		Short: "Show user's info",
		Run: func(cmd *cobra.Command, args []string) {
			data := queryUserInfo()
			if jsonFlag {
				jsonBytes, _ := json.Marshal(data)
				fmt.Println(string(jsonBytes))
			} else {
				fmt.Printf("Username: %v\nPermissions: %v\nVPC: %v", data["username"], data["permission"], data["vpc"])
			}
		},
	}
	var cmdList = &cobra.Command{
		Use:   "list",
		Short: "List user's applications",
		Long:  "List user's applications, including all auditable applications if have permission",
		Run: func(cmd *cobra.Command, args []string) {
			appList := queryAppList()
			if jsonFlag {
				jsonBytes, _ := json.Marshal(appList)
				fmt.Println(string(jsonBytes))
			} else {
				fmt.Printf("%8v %15v %15v %15v %7v\n", "id", "user", "src", "dst", "status")
				for _, app := range appList {
					fmt.Printf("%8v %15v %15v %15v %7v\n", app.Id, app.User, app.Src, app.Dst, app.Status)
				}
			}
		},
	}
	var cmdViewApp = &cobra.Command{
		Use:   "view",
		Short: "Show application details",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) <= 0 {
				return fmt.Errorf("should specify at least one application id")
			}
			for _, arg := range args {
				if _, err := strconv.Atoi(arg); err != nil {
					return fmt.Errorf("incorrect application id: %v", arg)
				}
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			var idList []int
			for _, arg := range args {
				id, _ := strconv.Atoi(arg)
				idList = append(idList, id)
			}
			appInfo := queryAppInfo(idList)
			if jsonFlag {
				jsonBytes, _ := json.Marshal(appInfo)
				fmt.Println(string(jsonBytes))
			} else {
				for id, infos := range appInfo {
					fmt.Printf("Application %v:\n", id)
					for _, info := range infos {
						fmt.Println(info.RelPath, info.Hash)
					}
				}
			}
		},
	}
	var saveFilePath string
	var cmdDownload = &cobra.Command{
		Use:   "download",
		Short: "Download files in application from server",
		Args: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if _, err := strconv.Atoi(arg); err != nil {
					return fmt.Errorf("incorrect application id: %v", arg)
				}
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			var idList []int
			for _, arg := range args {
				id, _ := strconv.Atoi(arg)
				idList = append(idList, id)
			}
			downloadFiles(idList, saveFilePath)
		},
	}
	cmdDownload.Flags().StringVarP(&saveFilePath, "out", "o", "./", "Specify download directory.")
	var cmdReviewApp = &cobra.Command{}
	var completion = &cobra.Command{
		Use: "completion",
	}
	completion.Hidden = true
	rootCmd.AddCommand(cmdInfo, cmdList, cmdViewApp, cmdDownload, cmdReviewApp, completion)
	rootCmd.Execute()
}
