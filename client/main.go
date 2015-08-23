/*/ // ===========================================================================
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2015 Bluek404
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
/*/ // ===========================================================================

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Unknwon/goconfig"
)

const VERSION = "2.0.3"

const (
	verSocks5 = 0x05

	atypIPv4Address = 0x01
	atypDomainName  = 0x03
	atypIPv6Address = 0x04

	reqtypeTCP  = 0x01
	reqtypeBIND = 0x02
	reqtypeUDP  = 0x03
)

var ipv4Reg = regexp.MustCompile(`(?:[0-9]+\.){3}[0-9]+`)

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
	log.Println("程序版本:" + VERSION)
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
	if err = s.updateSession(); err != nil {
		log.Println("与服务器连接失败:", err)
		return
	}
	log.Println("登录成功,服务器连接完毕")
	go s.updateSessionLoop()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go s.handleConnection(conn)
	}
}

type serve struct {
	serverHost        string
	serverPort        string
	key               string
	session           []byte
	nextUpdateTime    uint16
	updateSessionLock bool
	conf              *tls.Config
}

func (s *serve) updateSessionLoop() {
	for {
		time.Sleep(time.Second * time.Duration(s.nextUpdateTime))
		err := s.updateSession()
		if err != nil {
			log.Println(err)
		}
	}
}

func (s *serve) updateSession() error {
	if s.updateSessionLock {
		return nil
	}
	s.updateSessionLock = true
	defer func() { s.updateSessionLock = false }()

	/*
		+------+---------+----------+
		| TYPE | KEY LEN | KEY      |
		+------+---------+----------+
		| 1    | 2       | Variable |
		+------+---------+----------+

		- TYPE: 请求类型。0为session请求，1为代理请求
		- KEY LEN: KEY的长度，使用大端字节序，uint16
		- KEY: 身份验证用的KEY。字符串
	*/
	buf := bytes.NewBuffer([]byte{0})
	err := binary.Write(buf, binary.BigEndian, uint16(len(s.key)))
	if err != nil {
		return err
	}
	_, err = buf.WriteString(s.key)
	if err != nil {
		return err
	}

	conn, err := tls.Dial("tcp", s.serverHost+":"+s.serverPort, s.conf)
	if err != nil {
		return err
	}
	defer conn.Close()

	request := buf.Bytes()
	_, err = conn.Write(request)
	if err != nil {
		return err
	}

	/*
		+------+---------+-----+
		| CODE | SESSION | NPT |
		+------+---------+-----+
		| 1    | 64      | 2   |
		+------+---------+-----+

		- CODE: 状态码。0为成功，1为KEY验证失败
		- SESSION: 代理请求时使用的session。随机的64位字节
		- NPT: 多少秒后更新session，使用大端字节序，uint16
	*/
	buffer := make([]byte, 67)
	n, err := conn.Read(buffer)
	if err != nil {
		return err
	}
	if n != 67 {
		return errors.New("服务端应答长度非法")
	}
	if buffer[0] != 0 {
		return errors.New("KEY 验证失败")
	}

	s.session = buffer[1:65]
	s.nextUpdateTime = binary.BigEndian.Uint16(buffer[65:])
	log.Println("Session 更新完成，下次更新时间:",
		time.Unix(time.Now().Unix()+int64(s.nextUpdateTime), 0).
			Format("2006/01/02 15:04:05"))
	return nil
}

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
		conn.Write([]byte{5, 0})
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
	var reqtype string
	switch buf[1] {
	case reqtypeTCP:
		reqtype = "tcp"
	case reqtypeBIND:
		log.Println("暂不支持 BIND 命令（估计以后也不会支持）")
		conn.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		conn.Close()
		return
	case reqtypeUDP:
		reqtype = "udp"
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

	log.Println(conn.RemoteAddr(), "<="+reqtype+"=>", host+":"+strconv.Itoa(int(port)), "[+]")
	if reqtype == "tcp" {
		s.proxyTCP(conn, host, port)
	} else {
		s.proxyUDP(conn, host, port)
	}
}

func (s *serve) proxyTCP(conn net.Conn, host string, port uint16) {
	// 与服务端建立链接
	pconn, err := tls.Dial("tcp", s.serverHost+":"+s.serverPort, s.conf)
	if err != nil {
		log.Println("连接服务端失败:", err)
		conn.Close()
		return
	}
	/*
		+------+---------+-----+----------+----------+------+
		| TYPE | SESSION | CMD | HOST LEN | HOST     | PORT |
		+------+---------+-----+----------+----------+------+
		| 1    | 64      | 1   | 1        | Variable | 2    |
		+------+---------+-----+----------+----------+------+

		- TYPE: 请求类型。0为session请求，1为代理请求
		- SESSION: 身份验证用session，随机的64位字节
		- CMD: 协议类型。0为TCP，1为UDP
		- HOST LEN: 目标地址的长度
		- HOST: 目标地址，IPv[4|6]或者域名
		- PORT: 目标端口，使用大端字节序
	*/
	buffer := bytes.NewBuffer([]byte{1})
	buffer.Write(s.session)
	buffer.WriteByte(0)
	byteHost := []byte(host)
	buffer.WriteByte(byte(len(byteHost)))
	buffer.Write(byteHost)
	buffer.Write(make([]byte, 2))
	request := buffer.Bytes()
	binary.BigEndian.PutUint16(request[len(request)-2:], port)
	_, err = pconn.Write(request)
	if err != nil {
		log.Println(err)
		pconn.Close()
		conn.Close()
		return
	}

	/*
		+------+
		| CODE |
		+------+
		| 1    |
		+------+

		- CODE: 状态码。0为成功，2为session无效，[1|3-5]为socks5相应状态码
	*/
	// 读取服务端返回状态
	buf := make([]byte, 1)
	_, err = pconn.Read(buf)
	if err != nil {
		log.Println(err)
		pconn.Close()
		conn.Close()
		return
	}

	// 检查session是否验证成功
	if buf[0] == 2 {
		log.Println("服务端验证失败")
		pconn.Close()
		conn.Close()
		// 重新登录
		s.updateSession()
		return
	}

	/*
		SOCKS5状态码:
		1: General SOCKS server failure
		3: Network unreachable
		4: Host unreachable
		5: Connection refused
	*/
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
		log.Println(conn.RemoteAddr(), "==tcp=>", host, "[×]")
		log.Println(conn.RemoteAddr(), "<=tcp==", host, "[×]")
		conn.Close()
		pconn.Close()
		return
	}

	go func() {
		io.Copy(conn, pconn)
		conn.Close()
		pconn.Close()
		log.Println(conn.RemoteAddr(), "==tcp=>", host, "[√]")
	}()

	go func() {
		io.Copy(pconn, conn)
		conn.Close()
		pconn.Close()
		log.Println(conn.RemoteAddr(), "<=tcp==", host, "[√]")
	}()
}

func (s *serve) proxyUDP(conn net.Conn, host string, port uint16) {
	// 与服务端建立链接
	pconn, err := tls.Dial("tcp", s.serverHost+":"+s.serverPort, s.conf)
	if err != nil {
		log.Println("连接服务端失败:", err)
		conn.Close()
		return
	}
	/*
		+------+---------+-----+
		| TYPE | SESSION | CMD |
		+------+---------+-----+
		| 1    | 64      | 1   |
		+------+---------+-----+

		- TYPE: 请求类型。0为session请求，1为代理请求
		- SESSION: 身份验证用session，随机的64位字节
		- CMD: 协议类型。0为TCP，1为UDP
	*/
	buffer := bytes.NewBuffer([]byte{1})
	buffer.Write(s.session)
	buffer.WriteByte(1)
	request := buffer.Bytes()
	_, err = pconn.Write(request)
	if err != nil {
		log.Println(err)
		pconn.Close()
		conn.Close()
		return
	}

	/*
		+------+
		| CODE |
		+------+
		| 1    |
		+------+

		- CODE: 状态码。0为成功，2为session无效，[1|3-5]为socks5相应状态码
	*/
	// 读取服务端返回状态
	buf := make([]byte, 1)
	_, err = pconn.Read(buf)
	if err != nil {
		log.Println(err)
		pconn.Close()
		conn.Close()
		return
	}

	// 检查session是否验证成功
	if buf[0] == 2 {
		log.Println("服务端验证失败")
		pconn.Close()
		conn.Close()
		// 重新登录
		s.updateSession()
		return
	}

	/*
		SOCKS5状态码:
		1: General SOCKS server failure
		3: Network unreachable
		4: Host unreachable
		5: Connection refused
	*/
	code := buf[0]

	// 检查状态码
	if code != 0 {
		log.Println(conn.RemoteAddr(), "==udp=>", host, "[×]")
		log.Println(conn.RemoteAddr(), "<=udp==", host, "[×]")
		conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
		conn.Close()
		pconn.Close()
		return
	}

	uconn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Println(err)
		conn.Write([]byte{1})
		conn.Close()
		pconn.Close()
		return
	}
	buffer = bytes.NewBuffer([]byte{5, code, 0})
	lAddr := conn.LocalAddr().String()
	lAddr = lAddr[:strings.LastIndex(lAddr, ":")]
	if ipv4Reg.MatchString(lAddr) {
		buffer.WriteByte(atypIPv4Address)
		ipv6 := net.ParseIP(lAddr)
		ipv4 := ipv6[len(ipv6)-4:]
		buffer.Write(ipv4)
	} else if strings.ContainsRune(lAddr, ':') {
		buffer.WriteByte(atypIPv6Address)
		buffer.Write(net.ParseIP(lAddr))
	} else {
		buffer.WriteByte(atypDomainName)
		byteAddr := []byte(lAddr)
		buffer.WriteByte(byte(len(byteAddr)))
		buffer.Write(byteAddr)
	}
	buffer.Write(make([]byte, 2))
	response := buffer.Bytes()
	strPort := uconn.LocalAddr().String()
	strPort = strPort[strings.LastIndex(lAddr, ":")+1:]
	lPort, err := strconv.Atoi(strPort)
	if err != nil {
		log.Println(err)
		conn.Close()
		pconn.Close()
		return
	}
	binary.BigEndian.PutUint16(response[len(response)-2:],
		uint16(lPort))
	// 回应消息
	_, err = conn.Write(response)
	if err != nil {
		log.Println(err)
		conn.Close()
		pconn.Close()
		uconn.Close()
		return
	}
	conn.Close()

	// TODO: 两个LOOP交换 uconn 与 pconn 的数据
}
