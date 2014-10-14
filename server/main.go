package main

import (
	"bytes"
	"crypto/tls"
	"encoding/gob"
	"errors"
	"github.com/Unknwon/goconfig"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

const (
	version = "0.4.2"
)
const (
	login = iota
	connection
)

func main() {
	//log.SetFlags(log.Lshortfile) // debug时开启

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
			log.Println("配置文件保存失败：", err)
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
		clients: make(map[string]interface{}),
	}

	// 加载完成后输出配置信息
	log.Println("|>>>>>>>>>>>>>>>|<<<<<<<<<<<<<<<|")
	log.Println("程序版本：" + version)
	log.Println("监听端口：" + port)
	log.Println("Key：" + key)
	log.Println("|>>>>>>>>>>>>>>>|<<<<<<<<<<<<<<<|")

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
	key     string
	clients map[string]interface{}
	keepit  map[string]chan bool
}

func (s *serve) handleConnection(conn net.Conn) {
	log.Println("[+]", conn.RemoteAddr())

	var handshake Handshake

	// 读取客户端发送数据
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Println(n, err)
		conn.Close()
		return
	}

	// 对数据解码
	err = decode(buf[:n], &handshake)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}
	switch handshake.Type {
	case login:
		// 接受到登录请求
		// 检查是否已经登录
		_, ok := s.clients[getIP(conn.RemoteAddr().String())]
		if ok {
			log.Println("重复登录：", conn.RemoteAddr().String())
			return
		}
		// 验证key
		if handshake.Value["key"] == s.key {
			log.Println("新的客户端加入：", conn.RemoteAddr().String())
			//验证成功，发送成功信息
			isOK(conn)

			// 将客户端IP地址添加进客户端列表
			s.clients[getIP(conn.RemoteAddr().String())] = nil

			defer conn.Close()

			// 接收心跳包
			for {
				// 设置接收心跳包超时时间
				conn.SetDeadline(time.Now().Add(time.Second * 65))
				buf := make([]byte, 1)
				_, err = conn.Read(buf)
				if err != nil {
					// 心跳包接收失败
					// 再次尝试接收
					conn.SetDeadline(time.Now().Add(time.Second * 10))
					_, err = conn.Read(buf)
					if err != nil {
						// 客户端断开链接，删除客户端IP
						log.Println("客户端断开链接：", err)
						delete(s.clients, getIP(conn.RemoteAddr().String()))
						return
					}
				}
				isOK(conn)
			}
		} else {
			// 客户端验证失败，输出key并返回失败信息
			log.Println(conn.RemoteAddr(), "验证失败，对方所使用的key：", handshake.Value["key"])
			isntOK(conn)
			return
		}
	case connection:
		// 验证客户端是否存在
		err := s.clientOnClientsList(conn)
		if err != nil {
			log.Println(err)
			return
		}
		// 输出信息
		log.Println(conn.RemoteAddr(), "=="+handshake.Value["reqtype"]+"=>", handshake.Value["url"])

		// connect
		pconn, err := net.Dial(handshake.Value["reqtype"], handshake.Value["url"])
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
			log.Println(conn.RemoteAddr(), "=="+handshake.Value["reqtype"]+"=>", handshake.Value["url"], "[√]")
		}()
		go func() {
			io.Copy(pconn, conn)
			pconn.Close()
			conn.Close()
			log.Println(conn.RemoteAddr(), "<="+handshake.Value["reqtype"]+"==", handshake.Value["url"], "[√]")
		}()
	default:
		log.Println("未知请求类型：", handshake.Type)
	}
}

func getIP(ip string) string {
	if strings.Contains(ip, ":") {
		ip = ip[:strings.Index(ip, ":")]
	}
	return ip
}

// 用于验证客户端是否存在
func (s *serve) clientOnClientsList(conn net.Conn) error {
	_, ok := s.clients[getIP(conn.RemoteAddr().String())]
	if !ok {
		// 客户端不存在，返回错误信息并且关闭链接
		// 输出非法连接者IP
		isntOK(conn)
		return errors.New("非法连接： " + conn.RemoteAddr().String())
	}
	// 客户端存在，返回成功信息
	isOK(conn)
	return nil
}

func isOK(conn net.Conn) {
	//写入成功信息
	_, err := conn.Write([]byte{0})
	if err != nil {
		//写入成功信息失败，输出错误然后关闭链接
		log.Println(err)
		conn.Close()
	}
}

func isntOK(conn net.Conn) {
	//写入失败信息并且关闭链接
	_, err := conn.Write([]byte{1})
	if err != nil {
		//写入失败信息失败，输出错误（反正都会关闭链接）
		log.Println(err)
	}
	conn.Close()
}

// 数据解码
func decode(data []byte, to interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(to)
}

type Handshake struct {
	Type  int
	Value map[string]string
}
