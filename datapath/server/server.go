package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-systemd/v22/journal"
)

var (
	crtFilePath = "./server.crt"
	keyFilePath = "./server.key"
	pubKeys     = []ed25519.PublicKey{}
)

// func addPermissionReq(userKey ed25519.PublicKey) {

// }

// func addFile(hash string) {

// }

func loadPubKeys() {
	pubKeyBytes, _ := os.ReadFile("./pubKey")
	block, _ := pem.Decode(pubKeyBytes)
	tmpKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
	pubKeys = append(pubKeys, tmpKey.(ed25519.PublicKey))
}

type appFile struct {
	Hash    string
	RelPath string
}

func checkSign(dataBytes []byte, signature []byte) ed25519.PublicKey {
	for _, pubKey := range pubKeys {
		if ok := ed25519.Verify(pubKey, dataBytes, signature); ok {
			return pubKey
		}
	}
	return nil
}

func checkFileExist(hash string) bool {
	return hash == ""
}

func createNewApplication(user ed25519.PublicKey, sendFileList []appFile) {
}

func saveFile(fileBytes []byte, hash string) error {
	savePath := "./tmp/" + hash
	os.MkdirAll("./tmp", 0755)
	saveFile, err := os.Create(savePath)
	if err != nil {
		journal.Print(journal.PriErr, "Save file error: %v\n", err)
		return err
	}
	_, err = saveFile.Write(fileBytes)
	if err != nil {
		journal.Print(journal.PriErr, "Write file error: %v\n", err)
		return err
	}
	return nil
}

func uploadServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		signature, err := hex.DecodeString(r.PostFormValue("signature"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		jsonBytes := []byte(r.PostFormValue("jsondata"))
		user := checkSign(jsonBytes, signature)
		if user == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var sendFileList []appFile
		err = json.Unmarshal(jsonBytes, &sendFileList)
		if err != nil {
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		createNewApplication(user, sendFileList)
		var needFileList []string
		for _, file := range sendFileList {
			if !checkFileExist(file.Hash) {
				needFileList = append(needFileList, file.Hash)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		returnBytes, _ := json.Marshal(needFileList)
		w.Write(returnBytes)
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		file, fileHeader, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		defer file.Close()
		fileBytes, err := io.ReadAll(file)
		if err != nil {
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		err = saveFile(fileBytes, fileHeader.Filename)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})
	return http.ListenAndServeTLS("0.0.0.0:9990", crtFilePath, keyFilePath, mux)
}

func downloadServer() {
	mux := http.NewServeMux()

	http.ListenAndServeTLS("0.0.0.0:9991", crtFilePath, keyFilePath, mux)
}

func main() {
	loadPubKeys()
	go func() {
		for {
			err := uploadServer()
			if err != nil {
				journal.Print(journal.PriErr, "Upload server error: %v\n", err)
			}
		}
	}()
	go downloadServer()
	for {
		time.Sleep(time.Hour)
	}
}
