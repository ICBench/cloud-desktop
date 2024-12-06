package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"datapath/utils"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

const (
	configPath    = "/usr/local/etc/dataPathClient/config.toml"
	caPoolPath    = "/usr/local/etc/dataPathClient/CApool"
	crtFilePath   = "/usr/local/etc/dataPathClient/cert/client.crt"
	keyFilePath   = "/usr/local/etc/dataPathClient/cert/client.key"
	loPrivKeyPath = "/usr/local/etc/dataPathClient/privKey"
)

var (
	loUserName string
	serverHost string
	caPool     = x509.NewCertPool()
	loPrivKey  = ed25519.PrivateKey{}
	client     = &http.Client{}
)

func queryUserInfo() map[string]string {
	host := fmt.Sprintf("https://%v:9991/self", serverHost)
	res := utils.SendReq(client, host, make(map[string][]byte), loUserName, &loPrivKey)
	if res.StatusCode != http.StatusOK {
		log.Printf("Send request failed http: %v\n", res.StatusCode)
		os.Exit(1)
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
	res := utils.SendReq(client, host, map[string][]byte{}, loUserName, &loPrivKey)
	if res.StatusCode != http.StatusOK {
		log.Printf("Send request failed http: %v\n", res.StatusCode)
		os.Exit(1)
	}
	data := utils.ParseRes(res)
	json.Unmarshal(data["applist"], &appList)
	return
}

func queryOneAppInfo(id int) (appInfo []utils.AppFile, err error) {
	host := fmt.Sprintf("https://%v:9991/appinfo", serverHost)
	res := utils.SendReq(client, host, map[string][]byte{"id": []byte(strconv.Itoa(id))}, loUserName, &loPrivKey)
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

func downloadFiles(idList []string, basePath string) (allowedAppList, rejectedAppList []string) {
	host := fmt.Sprintf("https://%v:9991/download", serverHost)
	idListBytes, _ := json.Marshal(idList)
	res := utils.SendReq(client, host, map[string][]byte{"appidlist": idListBytes}, loUserName, &loPrivKey)
	data := utils.ParseRes(res)
	var fileList map[string][]utils.AppFile
	json.Unmarshal(data["allowedapplist"], &allowedAppList)
	json.Unmarshal(data["rejectedapplist"], &rejectedAppList)
	json.Unmarshal(data["filelist"], &fileList)
	accessKeyId := string(data["accesskeyid"])
	accessKeySecret := string(data["accesskeysecret"])
	securityToken := string(data["securitytoken"])
	endPoint := string(data["endpoint"])
	region := string(data["region"])
	ossClient, err := utils.NewOssClient(accessKeyId, accessKeySecret, securityToken, endPoint, region)
	if err != nil {
		log.Printf("Failed to create oss client: %v\n", err)
		os.Exit(1)
	}
	downloader := manager.NewDownloader(ossClient)
	basePath = filepath.Clean(basePath) + "/"
	for id, app := range fileList {
		appSavePath := basePath + id + "/"
		err := os.MkdirAll(appSavePath, 0755)
		if err != nil {
			log.Printf("Failed to access %v: %v", appSavePath, err)
			os.Exit(1)
		}
		for _, info := range app {
			fileSavePath := appSavePath + info.RelPath
			err := os.MkdirAll(filepath.Dir(fileSavePath), 0755)
			if err != nil {
				log.Printf("Failed to access %v: %v", fileSavePath, err)
				os.Exit(1)
			}
			file, err := os.Create(fileSavePath)
			if err != nil {
				log.Printf("Failed to access %v: %v", fileSavePath, err)
				os.Exit(1)
			}
			defer file.Close()
			header, err := ossClient.HeadObject(context.TODO(), &s3.HeadObjectInput{
				Bucket: aws.String(string(data["ossbucket"])),
				Key:    aws.String(id + "/" + info.Hash),
			})
			if err != nil {
				log.Printf("Failed to get file info: %v\n", file.Name())
				continue
			}
			bar := progressbar.DefaultBytes(
				aws.ToInt64(header.ContentLength),
				fmt.Sprintf("Downloading %v", file.Name()),
			)
			body := utils.FileBar{File: file, Bar: bar}
			_, err = downloader.Download(context.TODO(), body, &s3.GetObjectInput{
				Bucket: aws.String(string(data["ossbucket"])),
				Key:    aws.String(id + "/" + info.Hash),
			})
			if err != nil {
				log.Printf("Failed to download file: %v\n", file.Name())
			}
			fmt.Println()
		}
	}
	return
}

func reviewApp(appIdList []string, status string) map[string]string {
	host := fmt.Sprintf("https://%v:9991/review", serverHost)
	appIdListBytes, _ := json.Marshal(appIdList)
	res := utils.SendReq(client, host, map[string][]byte{"appidlist": appIdListBytes, "status": []byte(status)}, loUserName, &loPrivKey)
	data := utils.ParseRes(res)
	if res.StatusCode != http.StatusOK {
		log.Printf("http %v: %v", res.StatusCode, string(data["error"]))
		os.Exit(1)
	}
	reviewStat := make(map[string]string)
	json.Unmarshal(data["reviewstat"], &reviewStat)
	return reviewStat
}

func listVpc() []utils.VpcInfo {
	host := fmt.Sprintf("https://%v:9991/listvpc", serverHost)
	var vpcList []utils.VpcInfo
	res := utils.SendReq(client, host, map[string][]byte{}, loUserName, &loPrivKey)
	data := utils.ParseRes(res)
	if res.StatusCode != http.StatusOK {
		log.Printf("http %v: %v", res.StatusCode, string(data["error"]))
		os.Exit(1)
	}
	json.Unmarshal(data["vpclist"], &vpcList)
	return vpcList
}

func listUserByVpcId(vpcId int) []utils.UserInfo {
	host := fmt.Sprintf("https://%v:9991/listuser", serverHost)
	var userList []utils.UserInfo
	res := utils.SendReq(client, host, map[string][]byte{"vpcid": []byte(strconv.Itoa(vpcId))}, loUserName, &loPrivKey)
	data := utils.ParseRes(res)
	if res.StatusCode != http.StatusOK {
		log.Printf("http %v: %v", res.StatusCode, string(data["error"]))
		os.Exit(1)
	}
	json.Unmarshal(data["userlist"], &userList)
	return userList
}

func authUser(user string, vpcId int, permission int) utils.UserInfo {
	host := fmt.Sprintf("https://%v:9991/authuser", serverHost)
	res := utils.SendReq(client, host, map[string][]byte{"user": []byte(user), "vpcid": []byte(strconv.Itoa(vpcId)), "permission": []byte(strconv.Itoa(permission))}, loUserName, &loPrivKey)
	data := utils.ParseRes(res)
	if res.StatusCode != http.StatusOK {
		log.Printf("http %v: %v", res.StatusCode, string(data["error"]))
		os.Exit(1)
	}
	var userInfo utils.UserInfo
	json.Unmarshal(data["userinfo"], &userInfo)
	return userInfo
}

func startGUI() {

}

func main() {
	utils.LoadConfig(configPath, map[string]*string{
		"username": &loUserName,
		"host":     &serverHost,
	})
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
			allowedAppList, rejectedAppList := downloadFiles(args, saveFilePath)
			if jsonFlag {
				var data = map[string][]string{"allowed": allowedAppList, "rejected": rejectedAppList}
				dataBytes, _ := json.Marshal(data)
				fmt.Println(string(dataBytes))
			} else {
				if len(allowedAppList) > 0 {
					fmt.Printf("Allowed applications:\n%v\n", allowedAppList)
				} else {
					fmt.Println("No allowed application")
				}
				if len(rejectedAppList) > 0 {
					fmt.Printf("Rejected applications:\n%v\n", rejectedAppList)
				} else {
					fmt.Println("No rejected application")
				}
			}
		},
	}
	cmdDownload.Flags().StringVarP(&saveFilePath, "out", "o", "./", "Specify download directory.")
	cmdDownload.MarkFlagDirname("out")
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
	var cmdVpc = &cobra.Command{
		Use:   "vpc",
		Short: "Show VPC list",
		Run: func(cmd *cobra.Command, args []string) {
			vpcList := listVpc()
			if jsonFlag {
				jsonBytes, _ := json.Marshal(vpcList)
				fmt.Println(string(jsonBytes))
			} else {
				fmt.Printf("%5v %20v %20v\n", "ID", "VPC name", "CIDR")
				for _, info := range vpcList {
					fmt.Printf("%5v %20v %20v\n", info.Id, info.Name, info.Cidr)
				}
			}
		},
	}
	var vpcId int
	var cmdUser = &cobra.Command{
		Use:   "user",
		Short: "Show users in specified VPC",
		Run: func(cmd *cobra.Command, args []string) {
			userList := listUserByVpcId(vpcId)
			if jsonFlag {
				jsonBytes, _ := json.Marshal(userList)
				fmt.Println(string(jsonBytes))
			} else {
				fmt.Printf("%20v %120v %10v\n", "Username", "Public key", "Permission")
				for _, info := range userList {
					fmt.Printf("%20v %120v %10v\n", info.Name, strings.Replace(info.Key, "\n", `\n`, -1), info.Permission)
				}
			}
		},
	}
	cmdUser.Flags().IntVarP(&vpcId, "vpcid", "v", 0, "Specifiy VPC ID")
	cmdUser.MarkFlagRequired("vpcid")
	var keyStr string
	var permission int
	var cmdAuthUser = &cobra.Command{
		Use:   "auth",
		Short: "Authorize user",
		Run: func(cmd *cobra.Command, args []string) {
			keyStr = strings.Replace(keyStr, `\n`, "\n", -1)
			userInfo := authUser(keyStr, vpcId, permission)
			if jsonFlag {
				jsonBytes, _ := json.Marshal(userInfo)
				fmt.Println(string(jsonBytes))
			} else {
				fmt.Printf("Authorized %v(public key: %v) permission %v\n", userInfo.Name, strings.Replace(userInfo.Key, "\n", `\n`, -1), userInfo.Permission)
			}
		},
	}
	cmdAuthUser.Flags().IntVarP(&vpcId, "vpcid", "v", 0, "Specify VPC ID")
	cmdAuthUser.MarkFlagRequired("vpcid")
	cmdAuthUser.Flags().StringVarP(&keyStr, "user", "u", "", "Specify user by user's public key")
	cmdAuthUser.MarkFlagRequired("user")
	cmdAuthUser.Flags().IntVarP(&permission, "permission", "p", 0, "Specify permission")
	cmdAuthUser.MarkFlagRequired("permission")
	var completion = &cobra.Command{
		Use: "completion",
	}
	completion.Hidden = true
	rootCmd.AddCommand(cmdInfo, cmdList, cmdViewApp, cmdDownload, cmdReviewApp, cmdVpc, cmdUser, cmdAuthUser, completion)
	rootCmd.Execute()
}
