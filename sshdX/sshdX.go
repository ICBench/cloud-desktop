package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/coreos/go-systemd/v22/journal"
	"golang.org/x/crypto/ssh"
)

const (
	authorizedKeyPath = "/usr/local/etc/sshdX/authorized_keys"
	forceCmdPath      = "/usr/local/bin/forceCmd"
)

func loadAuthorizedKeys() map[string]bool {
	authorizedKeysBytes, err := os.ReadFile(authorizedKeyPath)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to load authorized_keys, err: %v", err)
		os.Exit(1)
	}
	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			log.Fatal(err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}
	return authorizedKeysMap
}

func loadConfig() ssh.ServerConfig {
	authorizedKeysMap := loadAuthorizedKeys()
	conf := ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}
	privKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to generate host key, err: %v", err)
		os.Exit(1)
	}
	signer, _ := ssh.NewSignerFromKey(privKey)
	conf.AddHostKey(signer)
	return conf
}

func removeInvisibleChar(src string) string {
	var builder strings.Builder
	for _, c := range src {
		if unicode.IsPrint(c) && !unicode.IsControl(c) {
			builder.WriteRune(c)
		}
	}
	return builder.String()
}

func handleSessionChannel(newChan ssh.NewChannel) {
	sshChan, reqs, err := newChan.Accept()
	if err != nil {
		journal.Print(journal.PriNotice, "Failed to accept channel: %v", err)
		return
	}
	defer sshChan.Close()
	for req := range reqs {
		fmt.Println(req.Type, req.WantReply)
		switch req.Type {
		case "exec":
			sshOriginalCmd := removeInvisibleChar(string(req.Payload[4:]))
			sshCmd := exec.Command(forceCmdPath)
			sshCmd.Env = append(sshCmd.Env, fmt.Sprintf("SSH_ORIGINAL_COMMAND=%v", sshOriginalCmd))
			out, _ := sshCmd.CombinedOutput()
			req.Reply(true, nil)
			sshChan.Write(out)
			sshChan.CloseWrite()
		default:
			req.Reply(false, nil)
		}
	}
}

func handleDirectTcpipChannel(newChan ssh.NewChannel) {
	extraData := newChan.ExtraData()
	port := binary.BigEndian.Uint32(extraData[13:17])
	portCheckCmd := exec.Command("lsof", "-i:"+strconv.Itoa(int(port)), "-sTCP:LISTEN", "-t")
	pidBytes, err := portCheckCmd.Output()
	if err != nil {
		failInfo := fmt.Sprintf("Fail to get program info on port %v", port)
		journal.Print(journal.PriErr, failInfo)
		newChan.Reject(ssh.ConnectionFailed, failInfo)
		return
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/%v/exe", strings.TrimSuffix(string(pidBytes), "\n")))
	if err != nil {
		failInfo := fmt.Sprintf("Fail to get program info on port %v", port)
		journal.Print(journal.PriErr, failInfo)
		newChan.Reject(ssh.ConnectionFailed, failInfo)
		return
	}
	absPath, _ := filepath.Abs(path)
	if absPath != "/usr/bin/x2gokdrive" {
		failInfo := "Forbidden program"
		journal.Print(journal.PriErr, failInfo)
		newChan.Reject(ssh.ConnectionFailed, failInfo)
		return
	}
	sshChan, _, err := newChan.Accept()
	if err != nil {
		failInfo := "Failed to accept channel"
		journal.Print(journal.PriErr, failInfo)
		newChan.Reject(ssh.ConnectionFailed, failInfo)
		return
	}
	defer sshChan.Close()
	localChan, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		Port: int(port),
	})
	if err != nil {
		failInfo := "Failed to establish connection"
		journal.Print(journal.PriErr, failInfo)
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		io.Copy(sshChan, localChan)
		wg.Done()
	}()
	go func() {
		io.Copy(localChan, sshChan)
		wg.Done()
	}()
	wg.Wait()
}

func handleChannels(sshConn *ssh.ServerConn, sshChans <-chan ssh.NewChannel) {
	for newChan := range sshChans {
		switch newChan.ChannelType() {
		case "session":
			go handleSessionChannel(newChan)
		case "direct-tcpip":
			go handleDirectTcpipChannel(newChan)
		default:
			newChan.Reject(ssh.Prohibited, "Reject!")
		}
	}
	sshConn.Close()
}
func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:2200")
	if err != nil {
		journal.Print(journal.PriErr, "Failed to listen port 2200")
		os.Exit(1)
	}
	serverConf := loadConfig()
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			journal.Print(journal.PriNotice, "Failed to accept connection: %v", err)
			continue
		}
		sshConn, sshChans, sshReq, err := ssh.NewServerConn(tcpConn, &serverConf)
		if err != nil {
			journal.Print(journal.PriNotice, "Failed to handshake: %v", err)
			tcpConn.Close()
			continue
		}
		go ssh.DiscardRequests(sshReq)
		journal.Print(journal.PriNotice, "Connect with %v", sshConn.RemoteAddr().String())
		go handleChannels(sshConn, sshChans)
	}
}
