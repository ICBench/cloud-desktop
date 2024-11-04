package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-systemd/v22/journal"
	_ "github.com/go-sql-driver/mysql"
)

var (
	crtFilePath = "./server.crt"
	keyFilePath = "./server.key"
	pubKeys     = []ed25519.PublicKey{}
	db          *sql.DB
)

type appFile struct {
	Hash    string
	RelPath string
}

func connectDb() {
	var err error
	db, err = sql.Open("mysql", "shizhao:icbench@tcp(127.0.0.1:3306)/data_path_server")
	if err != nil {
		journal.Print(journal.PriErr, "Failed to connect database: %v\n", err)
		os.Exit(-1)
	}
	err = db.Ping()
	if err != nil {
		journal.Print(journal.PriErr, "Failed to connect database: %v\n", err)
		os.Exit(-1)
	}
}

func loadPubKeys() {
	keyCows, err := db.Query("SELECT public_key FROM users")
	if err != nil {
		journal.Print(journal.PriErr, "Failed to get pubkey from database: %v\n", err)
		return
	}
	for keyCows.Next() {
		var keyStr string
		keyCows.Scan(&keyStr)
		pubKeyBytes := []byte(keyStr)
		block, _ := pem.Decode(pubKeyBytes)
		tmpKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			journal.Print(journal.PriErr, "Failed to parse pubkey: %v\n", err)
			continue
		}
		pubKeys = append(pubKeys, tmpKey.(ed25519.PublicKey))
	}
}

func checkFileExist(hash string) bool {
	rows, err := db.Query("SELECT hash FROM files WHERE hash = ?", hash)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to query file info from database: %v\n", err)
		return false
	}
	return rows.Next()
}

func createNewApplication(userKey ed25519.PublicKey, sendFileList []appFile) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(userKey)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to marshal public key: %v", err)
		return
	}
	user := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}))
	result, err := db.Exec("INSERT INTO applications (owner) VALUES (?)", user)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to create new application: %v", err)
		return
	}
	id, err := result.LastInsertId()
	if err != nil {
		journal.Print(journal.PriErr, "Failed to get application id: %v", err)
		return
	}
	for _, sendFile := range sendFileList {
		_, err := db.Exec("INSERT INTO application_file (file_hash,application_id,file_info) VALUES (?,?,?)", sendFile.Hash, id, sendFile.RelPath)
		if err != nil {
			journal.Print(journal.PriErr, "Failed to create new application: %v", err)
			return
		}
	}
}

func saveFile(fileBytes []byte, hash string) error {
	savePath := "./tmp/" + hash
	os.MkdirAll("./tmp", 0755)
	saveFile, err := os.Create(savePath)
	if err != nil {
		journal.Print(journal.PriErr, "Create file error: %v\n", err)
		return err
	}
	_, err = saveFile.Write(fileBytes)
	if err != nil {
		journal.Print(journal.PriErr, "Write file error: %v\n", err)
		return err
	}
	expTime := time.Now().AddDate(0, 30, 0)
	_, err = db.Exec("INSERT INTO files (hash,expiration_time) VALUES (?,?)", hash, expTime)
	if err != nil {
		journal.Print(journal.PriErr, "Update file database error: %v\n", err)
		return err
	}
	return nil
}

func checkSign(dataBytes []byte, signature []byte) ed25519.PublicKey {
	for _, pubKey := range pubKeys {
		if ok := ed25519.Verify(pubKey, dataBytes, signature); ok {
			return pubKey
		}
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
		var needFileList []string
		for _, file := range sendFileList {
			if !checkFileExist(file.Hash) {
				needFileList = append(needFileList, file.Hash)
			}
		}
		if len(needFileList) == 0 {
			createNewApplication(user, sendFileList)
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
		signature, err := hex.DecodeString(r.PostFormValue("signature"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		user := checkSign(fileBytes, signature)
		if user == nil {
			w.WriteHeader(http.StatusBadRequest)
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
	connectDb()
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
