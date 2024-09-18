# sshproxy
## 工作原理
首先作为服务器接收来自客户端的SSH连接，此时可以获取到连接的明文消息，对此进行过滤后，模拟客户端和真实服务器建立连接并转发SSH流量

## 配置文件
- config：位于~/.ssh/config，用于连接到真实服务器，ssh客户端的配置文件，至少应该配置Host、User、HostName、Port、IdentityFile五项
- authorized_key：位于/root/sshcs/.sshcs/authorized_key，用于保存客户端的公钥，可以类比SSHD的authorized_key格式进行创建
- DH_key：位于/root/sshcs/.sshcs/DH_key，用于与客户端连接时的D-H加密，使用ssh-keygen创建
- ports：位于/root/sshcs/.sshcs/ports，用于配置监听端口与真实服务器的对应关系，关系格式应该形如\<ip\>:\<port\> \<Host\>，每条关系一行且Host应该与config中对应