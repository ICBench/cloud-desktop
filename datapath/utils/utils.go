package utils

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/fs"
	"log"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"gopkg.in/yaml.v3"
)

const (
	PerReview = 1 << 1
	PerAdmin  = 1 << 2
)

type AppFile struct {
	Hash    string
	RelPath string
}

type AppInfo struct {
	Id       int
	User     string
	Status   int
	Src, Dst string
}

type VpcInfo struct {
	Id   int
	Cidr string
	Name string
}

type UserInfo struct {
	Name       string
	Key        string
	Permission int
}

func LoadCertsAndKeys(caPoolPath string, caPool *x509.CertPool, loPrivKeyPath string, loPrivKey *ed25519.PrivateKey) {
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
	*loPrivKey = tmpkey.(ed25519.PrivateKey)
}

func LoadHttpClient(crtFilePath string, keyFilePath string, client *http.Client, caPool *x509.CertPool, port int) {
	cert, err := tls.LoadX509KeyPair(crtFilePath, keyFilePath)
	if err != nil {
		log.Println("Failed to load certs")
		os.Exit(-1)
	}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{cert},
		},
		DialContext: (&net.Dialer{
			LocalAddr: &net.TCPAddr{
				Port: port,
			},
		}).DialContext,
	}
}

func SendReq(client *http.Client, host string, data map[string][]byte, userName string, loPrivKey *ed25519.PrivateKey) *http.Response {
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
	signature := ed25519.Sign(*loPrivKey, jsonBytes)
	bufWriter.WriteField("username", userName)
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

func ParseRes(res *http.Response) (data map[string][]byte) {
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

func NewOssClient(accessKeyId, accessKeySecret, securityToken string, useIn bool) *s3.Client {
	creds := credentials.NewStaticCredentialsProvider(accessKeyId, accessKeySecret, securityToken)
	cfg, _ := config.LoadDefaultConfig(context.TODO(), config.WithCredentialsProvider(creds))
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if useIn {
			o.BaseEndpoint = aws.String("https://s3.oss-cn-shanghai-internal.aliyuncs.com")
		} else {
			o.BaseEndpoint = aws.String("https://s3.oss-cn-shanghai.aliyuncs.com")
		}
		o.Region = "cn-shanghai"
	})
	return client
}

func InetAtoN(ipStr string) uint {
	ip := net.ParseIP(ipStr)
	tmp := big.NewInt(0).SetBytes(ip.To4())
	return uint(tmp.Int64())
}

func LoadConfig(configPath string, serverHost *string, loUserName *string) {
	configFile, err := os.Open(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Println("Failed to access the config file.")
		}
		return
	}
	configBytes, _ := io.ReadAll(configFile)
	config := make(map[string]interface{})
	yaml.Unmarshal(configBytes, config)
	if ifce, exist := config["host"]; exist {
		*serverHost = ifce.(string)
	}
	if ifce, exist := config["username"]; exist {
		*loUserName = ifce.(string)
	}
}
