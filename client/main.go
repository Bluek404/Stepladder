package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"github.com/Unknwon/goconfig"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"time"
)

const (
	version = "1.0.0"

	verSocks5 = 0x05

	atypIPv4Address = 0x01
	atypDomainName  = 0x03
	atypIPv6Address = 0x04

	reqtypeTCP  = 0x01
	reqtypeBIND = 0x02
	reqtypeUDP  = 0x03
)
const (
	login = iota
	connection
)

var (
	// 用于判断是否正在重新登录中
	reLogin bool

	// 统计发送心跳包线程的数量
	// 采用统计数量而不是bool判断是否存在的原因是
	// 客户端与服务器有可能短时间内重复多次链接+断开导致有多个线程未结束
	// 用统计数量的话就可以挨个结束了
	heartbeatGoroutine int
)

func main() {
	// 读取证书文件
	rootPEM, err := ioutil.ReadFile("cert.pem")
	if err != nil {
		log.Println("读取 cert.pem 出错:", err, "请检查文件是否存在")
		return
	}
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(rootPEM)
	if !ok {
		log.Println("证书分析失败，请检查证书文件是否正确")
		return
	}

	// 加载配置文件
	cfg, err := goconfig.LoadConfigFile("client.ini")
	if err != nil {
		log.Println("配置文件加载失败，自动重置配置文件:", err)
		cfg, err = goconfig.LoadFromData([]byte{})
		if err != nil {
			log.Println(err)
			return
		}
	}

	var (
		port, ok1       = cfg.MustValueSet("client", "port", "7071")
		key, ok2        = cfg.MustValueSet("client", "key", "eGauUecvzS05U5DIsxAN4n2hadmRTZGBqNd2zsCkrvwEBbqoITj36mAMk4Unw6Pr")
		serverHost, ok3 = cfg.MustValueSet("server", "host", "localhost")
		serverPort, ok4 = cfg.MustValueSet("server", "port", "8081")
	)

	// 如果缺少配置则保存为默认配置
	if ok1 || ok2 || ok3 || ok4 {
		err = goconfig.SaveConfigFile(cfg, "client.ini")
		if err != nil {
			log.Println("配置文件保存失败:", err)
		}
	}

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	log.Println("|>>>>>>>>>>>>>>>|<<<<<<<<<<<<<<<|")
	log.Println("程序版本:" + version)
	log.Println("代理端口:" + port)
	log.Println("Key:" + key)
	log.Println("服务器地址:" + serverHost + ":" + serverPort)
	log.Println("|>>>>>>>>>>>>>>>|<<<<<<<<<<<<<<<|")

	s := &serve{
		serverHost: serverHost,
		serverPort: serverPort,
		key:        key,
		conf: &tls.Config{
			RootCAs: roots,
		},
	}

	// 登录
	if err = s.handshake(); err != nil {
		log.Println("与服务器链接失败:", err)
		return
	}
	log.Println("登录成功,服务器连接完毕")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func encode(data interface{}) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type serve struct {
	serverHost string
	serverPort string
	key        string
	conf       *tls.Config
}

func (s *serve) handshake() error {
	// 发送key登录
	pconn, ok, err := s.send(&Message{
		Type:  login,
		Value: map[string]string{"key": s.key},
	})
	if err != nil {
		return err
	}

	// 登录失败
	if !ok {
		return errors.New("与服务器验证失败，请检查key是否正确")
	}
	// 发送心跳包
	// 当发送错误时说明链接已断开
	// 会自动重新登录
	// 如果检测到其他心跳包线程
	// 说明已经有接替，结束本线程
	go func() {
		heartbeatGoroutine++
		defer func() {
			heartbeatGoroutine--
		}()

		for {
			// 心跳包发送间隔
			time.Sleep(time.Second * 60)
			_, err := pconn.Write([]byte{0})
			if err != nil {
				// 心跳包发送失败
				if heartbeatGoroutine > 1 {
					// 发送心跳包的线程大于1
					// 已经有新的心跳包线程
					// 结束本线程
					return
				} else {
					// 再次尝试发送
					_, err := pconn.Write([]byte{0})
					if err != nil {
						// 与服务器断开链接
						pconn.Close()
						log.Println("与服务端断开链接:", err)
						// 重新登录
						s.reLogin()
						return
					}
				}
			}
		}
	}()
	return nil
}

// 向服务器发送信息，返回信息为 建立的链接+是否操作成功+错误
func (s *serve) send(handshake *Message) (net.Conn, bool, error) {
	// 建立链接
	pconn, err := tls.Dial("tcp", s.serverHost+":"+s.serverPort, s.conf)
	if err != nil {
		return nil, false, err
	}

	// 编码
	enc, err := encode(handshake)
	if err != nil {
		pconn.Close()
		return nil, false, err
	}

	// 发送信息
	_, err = pconn.Write(enc)
	if err != nil {
		pconn.Close()
		return nil, false, err
	}

	// 读取服务端返回信息
	buf := make([]byte, 1)
	_, err = pconn.Read(buf)
	if err != nil {
		pconn.Close()
		return nil, false, err
	}

	// 检查服务端是否返回操作成功
	if buf[0] != 0 {
		return pconn, false, nil
	}

	return pconn, true, nil
}

// 处理浏览器发出的请求
func (s *serve) handleConnection(conn net.Conn) {
	log.Println("[+]", conn.RemoteAddr())

	// socks5握手部分，具体参见 RFC1928
	var buf = make([]byte, 1+1+255)
	_, err := conn.Read(buf)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}
	if buf[0] != verSocks5 {
		log.Println("使用的socks版本为", buf[0], "，需要为 5")
		return
	}

	// 发送METHOD选择信息
	_, err = conn.Write([]byte{5, 0})
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	// 接收客户端需求信息
	buf = make([]byte, 4)
	_, err = conn.Read(buf)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	// 判断协议
	var reqType string
	switch buf[1] {
	case reqtypeTCP:
		reqType = "tcp"
	case reqtypeBIND:
		log.Println("BIND")
	case reqtypeUDP:
		reqType = "udp"
	}

	// 读取目标host
	var host string
	switch buf[3] {
	case atypIPv4Address:
		buf = make([]byte, 4)
		_, err = conn.Read(buf)
		if err != nil {
			log.Println(err)
			conn.Close()
			return
		}
		host = net.IP(buf).String()
	case atypIPv6Address:
		buf = make([]byte, 16)
		_, err = conn.Read(buf)
		if err != nil {
			log.Println(err)
			conn.Close()
			return
		}
		host = net.IP(buf).String()
	case atypDomainName:
		// 读取域名长度
		buf = make([]byte, 1)
		_, err = conn.Read(buf)
		if err != nil {
			log.Println(err)
			conn.Close()
			return
		}
		// 根据读取到的长度读取域名
		buf = make([]byte, buf[0])
		_, err = conn.Read(buf)
		if err != nil {
			log.Println(err)
			conn.Close()
			return
		}
		host = string(buf)
	}
	// 读取端口
	var port uint16
	err = binary.Read(io.Reader(conn), binary.BigEndian, &port)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}
	host += ":" + strconv.Itoa(int(port))

	log.Println(conn.RemoteAddr(), "<="+reqType+"=>", host, "[+]")

	// 与服务端建立链接
	pconn, ok, err := s.send(&Message{
		Type:  connection,
		Value: map[string]string{"reqtype": reqType, "url": host},
	})
	if err != nil {
		log.Println("连接服务端失败:", err)
		conn.Close()
		return
	}

	// 检查服务端是否返回成功
	if !ok {
		log.Println("服务端验证失败")
		pconn.Close()
		conn.Close()
		// 重新登录
		s.reLogin()
		return
	}

	// 读取服务端返回状态
	buf = make([]byte, 1)
	_, err = pconn.Read(buf)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}
	code := buf[0]

	// 回应消息
	_, err = conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	// 检查状态码
	// 放在这里是因为要先回应消息
	if code != 0 {
		log.Println(conn.RemoteAddr(), "=="+reqType+"=>", host, "[×]")
		log.Println(conn.RemoteAddr(), "<="+reqType+"==", host, "[×]")
		return
	}

	go func() {
		io.Copy(conn, pconn)
		conn.Close()
		pconn.Close()
		log.Println(conn.RemoteAddr(), "=="+reqType+"=>", host, "[√]")
	}()

	go func() {
		io.Copy(pconn, conn)
		conn.Close()
		pconn.Close()
		log.Println(conn.RemoteAddr(), "<="+reqType+"==", host, "[√]")
	}()
}

// 重新登录
func (s *serve) reLogin() {
	// 检查是否已经在重新登录中
	if !reLogin {
		reLogin = true
		log.Println("正在重新登录")
		if err := s.handshake(); err != nil {
			log.Println("重新登录失败:", err)
			reLogin = false
			return
		}
		log.Println("重新登录成功,服务器连接完毕")
		reLogin = false
	}
}

type Message struct {
	Type  int
	Value map[string]string
}
