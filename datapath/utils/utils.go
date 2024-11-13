package utils

import (
	"bytes"
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
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
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

type UploadFile struct {
	Hash string
	Url  string
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
	caPool.AppendCertsFromPEM([]byte("-----BEGIN CERTIFICATE-----\nMIIB4DCCAYagAwIBAgIQfaQTy1UvE2nSmVdcBt6x+DAKBggqhkjOPQQDAjA6MRww\nGgYDVQQKExNDZXJ0Z2VuIERldmVsb3BtZW50MRowGAYDVQQLDBFyb290QHh1YnVu\ndHUyNC4wNDAeFw0yNDExMDUwNjAzMThaFw0yNTExMDUwNjAzMThaMDoxHDAaBgNV\nBAoTE0NlcnRnZW4gRGV2ZWxvcG1lbnQxGjAYBgNVBAsMEXJvb3RAeHVidW50dTI0\nLjA0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt2f2CQobGLrpG9xWCCvjlfJQ\nefnwQmnEs8mnaCTC5QeAqqRz8dN9CyoFktnT76U11yhW04wHBk+g/9CDUucAG6Nu\nMGwwDgYDVR0PAQH/BAQDAgKkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB\n/wQFMAMBAf8wHQYDVR0OBBYEFLfADvpqY/Mb+uetjzilEO6bzeZQMBUGA1UdEQQO\nMAyHBH8AAAGHBGoP7EEwCgYIKoZIzj0EAwIDSAAwRQIhAOVDtvm6T0iu8CfMgPiN\nAtlBwc+qteQ4qKRv8rCk2NJTAiAeVBJJoxXPL/EvyEtVFSUYd+qgvh/ri6cJRBVV\noFmAZA==\n-----END CERTIFICATE-----"))
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
	}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{cert},
		},
		DialContext: (&net.Dialer{
			LocalAddr: &net.TCPAddr{
				// Port: port,
			},
		}).DialContext,
	}
}

func SendReq(client *http.Client, host string, data map[string][]byte, loPrivKey *ed25519.PrivateKey) *http.Response {
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
