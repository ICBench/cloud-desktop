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

	"github.com/spf13/cobra"
)

var (
	serverHost    = "106.15.236.65"
	certFilePath  = "/usr/local/etc/outbox/certs"
	certPool      = x509.NewCertPool()
	client        *http.Client
	loPrivKeyPath = "/usr/local/etc/outbox/privKey"
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

func loadHttpClient() {
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
			DialContext: (&net.Dialer{
				LocalAddr: &net.TCPAddr{
					Port: 9993,
				},
			}).DialContext,
		},
	}
}

func writeAuth(bufWriter *multipart.Writer) {
	rndData := make([]byte, 512)
	rand.Read(rndData)
	signature := ed25519.Sign(loPrivKey, rndData)
	bufWriter.WriteField("signature", hex.EncodeToString(signature))
	bufWriter.WriteField("randdata", hex.EncodeToString(rndData))
}

func queryUserInfo() map[string]interface{} {
	host := fmt.Sprintf("https://%v:9991/self", serverHost)
	var buf bytes.Buffer
	bufWriter := multipart.NewWriter(&buf)
	writeAuth(bufWriter)
	bufWriter.Close()
	req, _ := http.NewRequest("POST", host, &buf)
	req.Header.Set("Content-Type", bufWriter.FormDataContentType())
	res, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to ask self info: %v\n", err)
		os.Exit(-1)
	}
	if res.StatusCode != http.StatusOK {
		log.Printf("Query failed http: %v\n", res.StatusCode)
		os.Exit(-1)
	}
	info := make(map[string]interface{})
	infoBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("Incorrect response: %v\n", err)
		os.Exit(-1)
	}
	err = json.Unmarshal(infoBytes, &info)
	if err != nil {
		log.Printf("Invalid response: %v\n", err)
		os.Exit(-1)
	}
	return info
}

type appRow struct {
	Id       int
	User     string
	Status   int8
	Src, Dst string
}

func queryAppList() (appList []appRow) {
	host := fmt.Sprintf("https://%v:9991/applist", serverHost)
	var buf bytes.Buffer
	bufWriter := multipart.NewWriter(&buf)
	writeAuth(bufWriter)
	bufWriter.Close()
	req, _ := http.NewRequest("POST", host, &buf)
	req.Header.Set("Content-Type", bufWriter.FormDataContentType())
	res, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to ask application list: %v\n", err)
		os.Exit(-1)
	}
	if res.StatusCode != http.StatusOK {
		log.Printf("Query failed http: %v\n", res.StatusCode)
		os.Exit(-1)
	}
	appListBytes, _ := io.ReadAll(res.Body)
	json.Unmarshal(appListBytes, &appList)
	return
}

func startGUI() {

}

func main() {
	loadCertsAndKeys()
	loadHttpClient()
	queryAppList()
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
			info := queryUserInfo()
			if jsonFlag {
				jsonBytes, _ := json.Marshal(info)
				fmt.Println(string(jsonBytes))
			} else {
				fmt.Printf("Username: %v\nPermissions: %v\nVPC: %v", info["username"], info["permission"], info["vpc"])
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
	var cmdDownload = &cobra.Command{}
	var completion = &cobra.Command{
		Use: "completion",
	}
	completion.Hidden = true
	rootCmd.AddCommand(cmdInfo, cmdList, cmdDownload, completion)
	rootCmd.Execute()
}
