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
	"encoding/binary"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Bluek404/Stepladder/aestcp"

	"github.com/Unknwon/goconfig"
)

const VERSION = "3.0.0"

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
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func readHostAndPort(atype byte, conn net.Conn) (host string, port uint16, err error) {
	switch atype {
	case atypIPv4Address:
		buf := make([]byte, 4)
		_, err = conn.Read(buf)
		if err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case atypIPv6Address:
		buf := make([]byte, 16)
		_, err = conn.Read(buf)
		if err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case atypDomainName:
		// 读取域名长度
		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		if err != nil {
			return "", 0, err
		}
		// 根据读取到的长度读取域名
		buf = make([]byte, buf[0])
		_, err = conn.Read(buf)
		if err != nil {
			return "", 0, err
		}
		host = string(buf)
	}
	// 读取端口
	err = binary.Read(io.Reader(conn), binary.BigEndian, &port)
	if err != nil {
		return "", 0, err
	}

	return host, port, nil
}

func timeoutLoop(t time.Duration, do func(), alive, exit chan bool) {
	select {
	case <-alive:
		timeoutLoop(t, do, alive, exit)
	case <-exit:
	case <-time.After(t):
		do()
	}
}

func newTimeouter(t time.Duration, do func()) (chan<- bool, chan<- bool) {
	alive := make(chan bool, 1)
	exit := make(chan bool, 1)
	go timeoutLoop(t, do, alive, exit)

	return alive, exit
}

type serve struct {
	serverHost string
	serverPort string
	key        string
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
	var reqtype uint16
	switch buf[1] {
	case reqtypeTCP:
		reqtype = reqtypeTCP
	case reqtypeBIND:
		log.Println("暂不支持 BIND 命令（估计以后也不会支持）")
		conn.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		conn.Close()
		return
	case reqtypeUDP:
		reqtype = reqtypeUDP
	}

	host, port, err := readHostAndPort(buf[3], conn)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	if reqtype == reqtypeTCP {
		s.proxyTCP(conn, host, port)
	} else {
		s.proxyUDP(conn, host, port)
	}
}

func (s *serve) proxyTCP(conn net.Conn, host string, port uint16) {
	log.Println(conn.RemoteAddr(), "<=tcp=>", host+":"+strconv.Itoa(int(port)), "[+]")
	// 与服务端建立链接
	pconn, err := aestcp.Dial("tcp", s.serverHost+":"+s.serverPort, []byte(s.key))
	if err != nil {
		log.Println("连接服务端失败:", err)
		conn.Close()
		return
	}
	/*
		+-----+----------+----------+------+
		| CMD | HOST LEN | HOST     | PORT |
		+-----+----------+----------+------+
		| 1   | 1        | Variable | 2    |
		+-----+----------+----------+------+

		- CMD: 协议类型。0为TCP，1为UDP
		- HOST LEN: 目标地址的长度
		- HOST: 目标地址，IPv[4|6]或者域名
		- PORT: 目标端口，使用大端字节序，uint16
	*/
	buffer := bytes.NewBuffer([]byte{0})
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

		- CODE: 状态码。0为成功，[1|3-5]为socks5相应状态码
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
	log.Println(conn.RemoteAddr(), "<=udp=>", "ALL", "[+]")
	// 与服务端建立链接
	pconn, err := aestcp.Dial("tcp", s.serverHost+":"+s.serverPort, []byte(s.key))
	if err != nil {
		log.Println("连接服务端失败:", err)
		conn.Close()
		return
	}
	/*
		+-----+
		| CMD |
		+-----+
		| 1   |
		+-----+

		- CMD: 协议类型。0为TCP，1为UDP
	*/
	_, err = pconn.Write([]byte{1})
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
		log.Println(conn.RemoteAddr(), "<=udp=>", "ALL", "[×]")
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
	buffer := bytes.NewBuffer([]byte{5, code, 0})
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
	strPort = strPort[strings.LastIndex(strPort, ":")+1:]
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

	rAddr, err := net.ResolveUDPAddr("udp", host+":"+strconv.Itoa(int(port)))
	if err != nil {
		log.Println(err)
		pconn.Close()
		uconn.Close()
		return
	}

	alive, exit := newTimeouter(time.Minute*1, func() {
		pconn.Close()
		uconn.Close()
	})

	go func() {
		for {
			buf := make([]byte, 4)
			_, addr, err := uconn.ReadFromUDP(buf)
			if err != nil {
				log.Println(err)
				break
			}
			if buf[3] != 0 || addr != rAddr {
				continue
			}
			alive <- true

			pHost, pPort, err := readHostAndPort(buf[3], conn)
			if err != nil {
				log.Println(err)
				break
			}
			buf = make([]byte, 4096)
			n, _, err := uconn.ReadFromUDP(buf)
			if err != nil {
				log.Println(err)
				break
			}

			/*
				+----------+----------+------+----------+----------+
				| HOST LEN | HOST     | PORT | DATA LEN | DATA     |
				+----------+----------+------+----------+----------+
				| 1        | Variable | 2    | 2        | Variable |
				+----------+----------+------+----------+----------+

				- HOST LEN: [目标|来源]地址的长度
				- HOST: [目标|来源]地址，IPv[4|6]或者域名
				- PORT: [目标|来源]端口，使用大端字节序，uint16
				- DATA LEN: 原始数据长度，使用大端字节序，uint16
				- DATA: 原始数据
			*/
			pHostBytes := []byte(pHost)
			buffer := bytes.NewBuffer([]byte{byte(len(pHostBytes))})
			buffer.Write(pHostBytes)
			b := make([]byte, 4)
			binary.BigEndian.PutUint16(b[:2], pPort)
			binary.BigEndian.PutUint16(b[2:], uint16(n))
			buffer.Write(b)
			buffer.Write(buf[:n])

			_, err = pconn.Write(buffer.Bytes())
			if err != nil {
				log.Println(err)
				break
			}
		}
		log.Println(conn.RemoteAddr(), "==udp=>", "ALL", "[√]")
		pconn.Close()
		uconn.Close()
		exit <- true
	}()

	go func() {
		for {
			/*
				+----------+----------+------+----------+----------+
				| HOST LEN | HOST     | PORT | DATA LEN | DATA     |
				+----------+----------+------+----------+----------+
				| 1        | Variable | 2    | 2        | Variable |
				+----------+----------+------+----------+----------+

				- HOST LEN: [目标|来源]地址的长度
				- HOST: [目标|来源]地址，IPv[4|6]或者域名
				- PORT: [目标|来源]端口，使用大端字节序，uint16
				- DATA LEN: 原始数据长度，使用大端字节序，uint16
				- DATA: 原始数据
			*/
			buf := make([]byte, 1)
			_, err := pconn.Read(buf)
			if err != nil {
				log.Println(err)
				break
			}
			alive <- true
			hostLen := buf[0]
			buf = make([]byte, hostLen)
			_, err = pconn.Read(buf)
			if err != nil {
				log.Println(err)
				break
			}
			host := string(buf)
			buf = make([]byte, 2)
			_, err = pconn.Read(buf)
			if err != nil {
				log.Println(err)
				break
			}
			port := buf
			buf = make([]byte, 4096)
			n, err := pconn.Read(buf)
			if err != nil {
				log.Println(err)
				break
			}

			buffer := bytes.NewBuffer([]byte{0, 0, 0})
			if ipv4Reg.MatchString(host) {
				buffer.WriteByte(atypIPv4Address)
				ipv6 := net.ParseIP(host)
				ipv4 := ipv6[len(ipv6)-4:]
				buffer.Write(ipv4)
			} else if strings.ContainsRune(host, ':') {
				buffer.WriteByte(atypIPv6Address)
				buffer.Write(net.ParseIP(host))
			} else {
				buffer.WriteByte(atypDomainName)
				byteAddr := []byte(host)
				buffer.WriteByte(byte(len(byteAddr)))
				buffer.Write(byteAddr)
			}
			buffer.Write(port)
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b, uint16(n))
			buffer.Write(b)
			buffer.Write(buf[:n])
			_, err = uconn.WriteToUDP(buffer.Bytes(), rAddr)
			if err != nil {
				log.Println(err)
				break
			}
		}
		log.Println(conn.RemoteAddr(), "<=udp==", "ALL", "[√]")
		pconn.Close()
		uconn.Close()
		exit <- true
	}()
}
