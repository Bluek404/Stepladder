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
	"encoding/binary"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/Unknwon/goconfig"
)

const VERSION = "2.0.3"

var r = rand.New(rand.NewSource(time.Now().UnixNano()))

func main() {
	// 读取配置文件
	cfg, err := goconfig.LoadConfigFile("server.ini")
	if err != nil {
		log.Println("配置文件加载失败，自动重置配置文件", err)
		cfg, err = goconfig.LoadFromData([]byte{})
		if err != nil {
			log.Println(err)
			return
		}
	}

	var (
		key, ok1  = cfg.MustValueSet("client", "key", "eGauUecvzS05U5DIsxAN4n2hadmRTZGBqNd2zsCkrvwEBbqoITj36mAMk4Unw6Pr")
		port, ok2 = cfg.MustValueSet("server", "port", "8081")
	)

	// 如果缺少配置则保存为默认配置
	if ok1 || ok2 {
		err = goconfig.SaveConfigFile(cfg, "server.ini")
		if err != nil {
			log.Println("配置文件保存失败:", err)
		}
	}

	// 读取公私钥
	cer, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Println(err)
		return
	}

	// 监听端口
	ln, err := tls.Listen("tcp", ":"+port, &tls.Config{
		Certificates: []tls.Certificate{cer},
	})
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	s := &serve{
		key:     key,
		clients: make(map[string]uint),
	}

	// 加载完成后输出配置信息
	log.Println("|>>>>>>>>>>>>>>>|<<<<<<<<<<<<<<<|")
	log.Println("程序版本:" + VERSION)
	log.Println("监听端口:" + port)
	log.Println("Key:" + key)
	log.Println("|>>>>>>>>>>>>>>>|<<<<<<<<<<<<<<<|")

	go s.genSession()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func to64ByteArray(s []byte) (result [64]byte) {
	if len(s) != 64 {
		panic(s)
	}
	for i, v := range s {
		result[i] = v
	}
	return result
}

func newSession() (result [64]byte) {
	for i := range result {
		result[i] = byte(r.Int31n(256))
	}
	return result
}

type serve struct {
	key            string
	session        [64]byte
	nextUpdateTime int64
	clients        map[string]uint
	keepit         map[string]chan bool
}

func (s *serve) genSession() {
	for {
		second := r.Int63n(5+1) * 60
		s.nextUpdateTime = time.Now().Unix() + second
		s.session = newSession()
		time.Sleep(time.Second * time.Duration(second))
	}
}

func (s *serve) handleConnection(conn net.Conn) {
	log.Println("[+]", conn.RemoteAddr())

	/*
		三种可能的请求:

		+------+---------+----------+
		| TYPE | KEY LEN | KEY      |
		+------+---------+----------+
		| 1    | 2       | Variable |
		+------+---------+----------+

		- TYPE: 请求类型。0为session请求，1为代理请求
		- KEY LEN: KEY的长度，使用大端字节序，uint16
		- KEY: 身份验证用的KEY。字符串

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
		- PORT: 目标端口，使用大端字节序，uint16

		+------+---------+-----+
		| TYPE | SESSION | CMD |
		+------+---------+-----+
		| 1    | 64      | 1   |
		+------+---------+-----+

		- TYPE: 请求类型。0为session请求，1为代理请求
		- SESSION: 身份验证用session，随机的64位字节
		- CMD: 协议类型。0为TCP，1为UDP
	*/
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil {
		log.Println(n, err)
		conn.Close()
		return
	}

	switch buf[0] {
	case 0:
		defer conn.Close()
		buf = make([]byte, 2)
		n, err = conn.Read(buf)
		if err != nil {
			log.Println(err)
			return
		}
		length := binary.BigEndian.Uint16(buf)
		buf = make([]byte, length)
		n, err = conn.Read(buf)
		if err != nil {
			log.Println(err)
			return
		}
		if n != int(length) {
			log.Println("错误的KEY长度")
			return
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
		key := string(buf)
		if key != s.key {
			log.Println("错误的KEY:", key)
			conn.Write([]byte{0})
			return
		}
		buffer := bytes.NewBuffer([]byte{0})
		buffer.Write(s.session[:])
		buffer.Write(make([]byte, 2))
		response := buffer.Bytes()
		binary.BigEndian.PutUint16(response[len(response)-2:],
			uint16(s.nextUpdateTime-time.Now().Unix()))
		_, err = conn.Write(response)
		if err != nil {
			log.Println(err)
			return
		}
	case 1:
		// 验证session
		buf = make([]byte, 64)
		n, err = conn.Read(buf)
		if err != nil {
			log.Println(err)
			conn.Close()
			return
		}
		if n != 64 {
			log.Println("错误的session长度:", n)
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
		if to64ByteArray(buf) != s.session {
			log.Println("session无效:", buf)
			conn.Write([]byte{2})
			conn.Close()
			return
		}
		// 读取协议类型
		buf = make([]byte, 1)
		_, err = conn.Read(buf)
		if err != nil {
			log.Println(err)
			conn.Close()
			return
		}
		if buf[0] == 0 {
			s.proxyTCP(conn)
		} else {
			s.proxyUDP(conn)
		}
	default:
		log.Println("未知请求类型:", buf[0])
		conn.Close()
	}
}

func (s *serve) proxyTCP(conn net.Conn) {
	// 读取host长度
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}
	hostLen := int(buf[0])
	// 读取host
	buf = make([]byte, hostLen)
	n, err := conn.Read(buf)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}
	if n != hostLen {
		log.Println("host长度错误")
		conn.Close()
		return
	}
	host := string(buf)
	// 读取port
	var port uint16
	err = binary.Read(conn, binary.BigEndian, &port)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	url := host + ":" + strconv.Itoa(int(port))

	// 输出信息
	log.Println(conn.RemoteAddr(), "<=tcp=>", url, "[+]")

	// connect
	pconn, err := net.Dial("tcp", url)
	if err != nil {
		log.Println(err)
		log.Println(conn.RemoteAddr(), "==tcp=>", url, "[×]")
		log.Println(conn.RemoteAddr(), "<=tcp==", url, "[×]")
		// 给客户端返回错误信息
		conn.Write([]byte{3})
		conn.Close()
		return
	}
	_, err = conn.Write([]byte{0})
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	// 两个conn互相传输信息
	go func() {
		io.Copy(conn, pconn)
		conn.Close()
		pconn.Close()
		log.Println(conn.RemoteAddr(), "==tcp=>", url, "[√]")
	}()
	go func() {
		io.Copy(pconn, conn)
		pconn.Close()
		conn.Close()
		log.Println(conn.RemoteAddr(), "<=tcp==", url, "[√]")
	}()
}

func (s *serve) proxyUDP(conn net.Conn) {
	pconn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Println(err)
		conn.Write([]byte{1})
		conn.Close()
		return
	}
	_, err = conn.Write([]byte{0})
	if err != nil {
		log.Println(err)
		pconn.Close()
		conn.Close()
		return
	}

	// TODO: 两个LOOP交换 conn 与 pconn 的数据
}
