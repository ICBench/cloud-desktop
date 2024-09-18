package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
)

const (
	authorizedKeyPath string = "/root/sshcs/.sshcs/authorized_key"
	DHKeyPath         string = "/root/sshcs/.sshcs/DH_key"
	port2HostPath     string = "/root/sshcs/.sshcs/ports"
)

type remoteDeskConfig struct {
	host    string
	address string
}

func loadAuthorizedKeys() map[string]bool {
	authorizedKeysBytes, err := os.ReadFile(authorizedKeyPath)
	if err != nil {
		log.Fatalf("Failed to load authorized_keys, err: %v", err)
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

func loadDHKey() ssh.Signer {
	privateKeyBytes, err := os.ReadFile(DHKeyPath)
	if err != nil {
		log.Fatalf("Failed to load private key,check %v", DHKeyPath)
	}
	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}
	return privateKey
}

func loadRemoteDesks() []remoteDeskConfig {
	port2HostBytes, err := os.ReadFile(port2HostPath)
	if err != nil {
		log.Fatalf("Failed to load port config,check %v", port2HostPath)
	}
	var remoteDesks []remoteDeskConfig
	port2Hosts := strings.Split(string(port2HostBytes), "\n")
	for _, port2Host := range port2Hosts {
		if len(port2Host) > 0 {
			tmp := strings.Split(string(port2Host), " ")
			remoteDesks = append(remoteDesks, remoteDeskConfig{address: tmp[0], host: tmp[1]})
		}
	}
	return remoteDesks
}

func main() {
	// 加载服务器配置（authorized_keys、D-H key、云桌面列表）
	authorizedKeysMap := loadAuthorizedKeys()
	serverConfig := &ssh.ServerConfig{
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
	serverConfig.AddHostKey(loadDHKey())
	remoteDesks := loadRemoteDesks()

	// 对云桌面列表中的每一个云桌面建立一个goroutine进行监听和处理
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, remoteDesk := range remoteDesks {
		wg.Add(1)
		go func() {
			sshserver(remoteDesk, serverConfig)
			wg.Done()
		}()
	}

}

// 监听请求和转发
func sshserver(remoteDesk remoteDeskConfig, serverConfig *ssh.ServerConfig) {
	// 加载用于连接到对应云桌面的信息
	host := remoteDesk.host
	identityfile := ssh_config.Get(host, "Identityfile")
	addr := ssh_config.Get(host, "HostName") + ":22"
	key, err := os.ReadFile(identityfile)
	if err != nil {
		log.Fatalf("Fail to load Identityfile %v", err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("Fail to prase Identityfile %v", err)
	}
	clientConfig := &ssh.ClientConfig{
		User: ssh_config.Get(host, "User"),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// 监听TCP连接
	listener, err := net.Listen("tcp", remoteDesk.address)
	if err != nil {
		log.Fatalf("Fail to listen on %v", remoteDesk.address)
	}
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		// 与客户端进行SSH握手，升级为SSH连接
		serverConn, serverChans, serverReqs, err := ssh.NewServerConn(tcpConn, serverConfig)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}
		go ssh.DiscardRequests(serverReqs)
		log.Printf("connected from %v\n", serverConn.RemoteAddr())

		// 向云桌面发送TCP连接
		tcpConn, err = net.Dial("tcp", addr)
		if err != nil {
			log.Printf("Failed to connect to server (%s)", err)
			continue
		}
		// 与云桌面进行SSH握手，升级为SSH连接
		clientConn, _, _, err := ssh.NewClientConn(tcpConn, addr, clientConfig)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}
		// 对客户端的试图建立的每一个Channel分别建立一个goroutine进行处理
		go func() {
			for newChannel := range serverChans {
				go handleChannel(newChannel, clientConn)
			}
		}()
	}
}

func handleChannel(newChannel ssh.NewChannel, clientConn ssh.Conn) {
	// 接受新Channel
	log.Printf("new channel: %v", newChannel.ChannelType())
	serverChan, serverReqs, err := newChannel.Accept()
	if err != nil {
		log.Fatalf("Fail to accept channel: %v", err)
	}
	// 在与服务器的SSH连接中使用新Channel的信息建立一个同样类型的Channel并对数据进行转发
	clientChan, _, err := clientConn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
	if err != nil {
		log.Fatalf("Fail to create channel: %v", err)
	}
	var once sync.Once
	disconnect := func() {
		serverChan.Close()
		clientChan.Close()
	}
	go func() {
		io.Copy(serverChan, clientChan)
		once.Do(disconnect)
	}()
	go func() {
		io.Copy(clientChan, serverChan)
		once.Do(disconnect)
	}()

	// 对Channel对应的Request进行筛选，通过筛选的原样发送到云桌面
	go func() {
		for req := range serverReqs {
			log.Printf("new request: %v", req.Type)
			if req.Type == "subsystem" {
				req.Reply(false, nil)
				continue
			}
			ok, err := clientChan.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Printf("fail to send request: %v", err)
			}
			if req.WantReply {
				req.Reply(ok, nil)
			}
		}
	}()
}
