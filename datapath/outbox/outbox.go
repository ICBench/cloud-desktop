package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"datapath/utils"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	serverHost    = "106.15.236.65"
	caPoolPath    = "/usr/local/etc/dataPathClient/CApool"
	caPool        = x509.NewCertPool()
	crtFilePath   = "/usr/local/etc/dataPathClient/certs/client.crt"
	keyFilePath   = "/usr/local/etc/dataPathClient/certs/client.key"
	client        = &http.Client{}
	loPrivKeyPath = "/usr/local/etc/dataPathClient/privKey"
	loPrivKey     = ed25519.PrivateKey{}
)

func queryUserInfo() map[string]string {
	host := fmt.Sprintf("https://%v:9991/self", serverHost)
	res := utils.SendReq(client, host, make(map[string][]byte), &loPrivKey)
	if res.StatusCode != http.StatusOK {
		log.Printf("Send request failed http: %v\n", res.StatusCode)
		os.Exit(-1)
	}
	data := utils.ParseRes(res)
	return map[string]string{
		"username":   string(data["username"]),
		"permission": string(data["permission"]),
		"vpc":        string(data["vpc"]),
	}
}

func queryAppList() (appList []utils.AppInfo) {
	host := fmt.Sprintf("https://%v:9991/applist", serverHost)
	res := utils.SendReq(client, host, map[string][]byte{}, &loPrivKey)
	if res.StatusCode != http.StatusOK {
		log.Printf("Send request failed http: %v\n", res.StatusCode)
		os.Exit(-1)
	}
	data := utils.ParseRes(res)
	json.Unmarshal(data["applist"], &appList)
	return
}

func queryOneAppInfo(id int) (appInfo []utils.AppFile, err error) {
	host := fmt.Sprintf("https://%v:9991/appinfo", serverHost)
	res := utils.SendReq(client, host, map[string][]byte{"id": []byte(strconv.Itoa(id))}, &loPrivKey)
	if res.StatusCode != http.StatusOK {
		log.Printf("Send request failed http: %v\n", res.StatusCode)
		return
	}
	data := utils.ParseRes(res)
	json.Unmarshal(data["appinfo"], &appInfo)
	sort.Slice(appInfo, func(i, j int) bool {
		return appInfo[i].RelPath < appInfo[j].RelPath
	})
	return
}

func queryAppInfo(idList []int) (appInfo map[int][]utils.AppFile) {
	appInfo = make(map[int][]utils.AppFile)
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

func downloadFile(fileName string, fileHash string, appId string, file *os.File) {
	host := fmt.Sprintf("https://%v:9991/download", serverHost)
	var sendData = map[string][]byte{
		"hash":  []byte(fileHash),
		"appid": []byte(appId),
	}
	res := utils.SendReq(client, host, sendData, &loPrivKey)
	data := utils.ParseRes(res)
	if res.StatusCode != http.StatusOK {
		log.Printf("Query failed http: %v %v\n", res.StatusCode, string(data["error"]))
		return
	}
	if string(data["hash"]) == fileHash {
		url := string(data["url"])
		res, err := client.Get(url)
		if err != nil {
			log.Printf("Failed to download file: %v\n", err)
			return
		}
		bar := progressbar.DefaultBytes(res.ContentLength, fmt.Sprintf("Downloading %v:", fileName))
		io.Copy(io.MultiWriter(file, bar), res.Body)
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
			downloadFile(info.RelPath, info.Hash, strconv.Itoa(id), file)
		}
	}
}

func reviewApp(appIdList []string, status string) map[string]string {
	host := fmt.Sprintf("https://%v:9991/review", serverHost)
	appIdListBytes, _ := json.Marshal(appIdList)
	res := utils.SendReq(client, host, map[string][]byte{"appidlist": appIdListBytes, "status": []byte(status)}, &loPrivKey)
	data := utils.ParseRes(res)
	if res.StatusCode != http.StatusOK {
		log.Printf("http %v: %v", res.StatusCode, string(data["error"]))
		os.Exit(-1)
	}
	reviewStat := make(map[string]string)
	json.Unmarshal(data["reviewstat"], &reviewStat)
	return reviewStat
}

func startGUI() {

}

func main() {
	utils.LoadCertsAndKeys(caPoolPath, caPool, loPrivKeyPath, &loPrivKey)
	utils.LoadHttpClient(crtFilePath, keyFilePath, client, caPool, 9993)
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
				for _, id := range idList {
					fmt.Printf("Application %v:\n", id)
					for _, info := range appInfo[id] {
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
	var cancelFlag bool
	var cmdReviewApp = &cobra.Command{
		Use:   "review",
		Short: "Review an application",
		Long:  "Review an application, will not take effect without permission",
		Args: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if _, err := strconv.Atoi(arg); err != nil {
					return fmt.Errorf("incorrect application id: %v", arg)
				}
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			var status string
			if cancelFlag {
				status = "1"
			} else {
				status = "0"
			}
			reviewStat := reviewApp(args, status)
			if jsonFlag {
				jsonBytes, _ := json.Marshal(reviewStat)
				fmt.Println(string(jsonBytes))
			} else {
				for _, id := range args {
					fmt.Printf("Appilcation %v review status: %v\n", id, reviewStat[id])
				}
			}
		},
	}
	cmdReviewApp.Flags().BoolVarP(&cancelFlag, "cancel", "c", false, "Cancel the passed application if specified this flag")
	var completion = &cobra.Command{
		Use: "completion",
	}
	completion.Hidden = true
	rootCmd.AddCommand(cmdInfo, cmdList, cmdViewApp, cmdDownload, cmdReviewApp, completion)
	rootCmd.Execute()
}
