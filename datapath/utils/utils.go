package utils

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	mathrand "math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/coreos/go-systemd/v22/journal"
)

const (
	PerReview = 1 << 1
	PerAdmin  = 1 << 2
)

var (
	maxRetryTimes = 10
	maxRetrySec   = 60
	iniRetrySec   = 1
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

type FileBar struct {
	File *os.File
	Bar  io.Writer
}

func (w FileBar) WriteAt(p []byte, off int64) (n int, err error) {
	w.Bar.Write(p)
	return w.File.WriteAt(p, off)
}

func (r FileBar) ReadAt(b []byte, off int64) (n int, err error) {
	n, err = r.File.ReadAt(b, off)
	r.Bar.Write(b)
	return
}

func (r FileBar) Read(b []byte) (n int, err error) {
	n, err = r.File.Read(b)
	r.Bar.Write(b)
	return
}

func (r FileBar) Seek(offset int64, whence int) (ret int64, err error) {
	return r.File.Seek(offset, whence)
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
		os.Exit(1)
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
		os.Exit(1)
	}
	return res
}

func ParseRes(res *http.Response) (data map[string][]byte) {
	data = make(map[string][]byte)
	jsonData := make(map[string]string)
	jsonBytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("Failed to parse response: %v\n", err)
		os.Exit(1)
	}
	err = json.Unmarshal(jsonBytes, &jsonData)
	if err != nil {
		return
	}
	for fieldName, fieldValue := range jsonData {
		data[fieldName], err = hex.DecodeString(fieldValue)
		if err != nil {
			continue
		}
	}
	return
}

func NewOssClient(accessKeyId, accessKeySecret, securityToken, endPoint, region string) (*s3.Client, error) {
	creds := credentials.NewStaticCredentialsProvider(accessKeyId, accessKeySecret, securityToken)
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithCredentialsProvider(creds))
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endPoint)
		o.Region = region
	})
	return client, nil
}

func InetAtoN(ipStr string) uint {
	ip := net.ParseIP(ipStr)
	tmp := big.NewInt(0).SetBytes(ip.To4())
	return uint(tmp.Int64())
}

func LoadConfig(confPath string, confList map[string]*string) {
	configFile, err := os.Open(confPath)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to access the config file: %v.", err)
		os.Exit(1)
	}
	configBytes, err := io.ReadAll(configFile)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to read the config file: %v.", err)
		os.Exit(1)
	}
	config := make(map[string]interface{})
	err = toml.Unmarshal(configBytes, &config)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to parse the config file: %v.", err)
		os.Exit(1)
	}
	for name, value := range confList {
		ifce, exist := config[name]
		if !exist {
			journal.Print(journal.PriErr, "Config file invalid: missing %v", name)
			os.Exit(1)
		}
		*value = ifce.(string)
	}
}

func TxBegin(db *sql.DB) (tx *sql.Tx, err error) {
	maxDuration := iniRetrySec
	for i := 1; i <= maxRetryTimes; i++ {
		tx, err = db.Begin()
		if err == nil {
			break
		}
		if i == maxRetryTimes || errors.Is(err, sql.ErrConnDone) {
			return nil, err
		}
		maxDuration = min(maxDuration*2, maxRetrySec)
		sleepSec := mathrand.Intn(maxDuration/2) + maxDuration/2
		time.Sleep(time.Second * time.Duration(sleepSec))
	}
	return
}

func TxOp(tx *sql.Tx, op string) (err error) {
	maxDuration := iniRetrySec
	for i := 1; i <= maxRetryTimes; i++ {
		switch op {
		case "Commit":
			err = tx.Commit()
		case "Rollback":
			err = tx.Rollback()
		default:
			err = fmt.Errorf("invalid operation")
			return
		}
		if err == nil {
			break
		}
		if i == maxRetryTimes || errors.Is(err, sql.ErrTxDone) {
			return err
		}
		maxDuration = min(maxDuration*2, maxRetrySec)
		sleepSec := mathrand.Intn(maxDuration/2) + maxDuration/2
		time.Sleep(time.Second * time.Duration(sleepSec))
	}
	return
}

func TxQuery(tx *sql.Tx, query string, args ...any) (rows *sql.Rows, err error) {
	maxDuration := iniRetrySec
	for i := 1; i <= maxRetryTimes; i++ {
		rows, err = tx.Query(query, args...)
		if err == nil {
			break
		}
		if i == maxRetryTimes || errors.Is(err, sql.ErrTxDone) {
			return nil, err
		}
		maxDuration = min(maxDuration*2, maxRetrySec)
		sleepSec := mathrand.Intn(maxDuration/2) + maxDuration/2
		time.Sleep(time.Second * time.Duration(sleepSec))
	}
	return
}

func DbQuery(db *sql.DB, query string, args ...any) (rows *sql.Rows, err error) {
	maxDuration := iniRetrySec
	for i := 1; i <= maxRetryTimes; i++ {
		rows, err = db.Query(query, args...)
		if err == nil {
			break
		}
		if i == maxRetryTimes || errors.Is(err, sql.ErrConnDone) {
			return nil, err
		}
		maxDuration = min(maxDuration*2, maxRetrySec)
		sleepSec := mathrand.Intn(maxDuration/2) + maxDuration/2
		time.Sleep(time.Second * time.Duration(sleepSec))
	}
	return
}

func DbExec(db *sql.DB, query string, args ...any) (result sql.Result, err error) {
	var tx *sql.Tx
	maxDuration := iniRetrySec
	for i := 1; i <= maxRetryTimes; i++ {
		tx, err = TxBegin(db)
		if err != nil {
			return nil, err
		}
		result, err = tx.Exec(query, args...)
		if err == nil {
			break
		}
		txErr := TxOp(tx, "Rollback")
		if i == maxRetryTimes || errors.Is(err, sql.ErrConnDone) || errors.Is(err, sql.ErrTxDone) {
			return nil, err
		}
		if txErr != nil {
			return nil, txErr
		}
		maxDuration = min(maxDuration*2, maxRetrySec)
		sleepSec := mathrand.Intn(maxDuration/2) + maxDuration/2
		time.Sleep(time.Second * time.Duration(sleepSec))
	}
	txErr := TxOp(tx, "Commit")
	if txErr != nil {
		TxOp(tx, "Rollback")
		return nil, txErr
	}
	return result, nil
}
