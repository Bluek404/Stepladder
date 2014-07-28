package main

import (
	"bytes"
	"crypto/tls"
	"encoding/gob"
	"github.com/Unknwon/goconfig"
	"io"
	"log"
	"net"
)

const (
	version = "0.1.9"
)

func main() {
	//log.SetFlags(log.Lshortfile)//debug时开启

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
		key, ok1  = cfg.MustValueSet("client", "key", "EbzHvwg8BVYz9Rv3")
		port, ok2 = cfg.MustValueSet("server", "port", "8081")
	)

	if ok1 == true || ok2 == true {
		err = goconfig.SaveConfigFile(cfg, "server.ini")
		if err != nil {
			log.Println("配置文件保存失败：", err)
		}
	}

	log.Println("|>>>>>>>>>>>>>>>|<<<<<<<<<<<<<<<|")
	log.Println("程序版本：" + version)
	log.Println("监听端口：" + port)
	log.Println("Key：" + key)
	log.Println("|>>>>>>>>>>>>>>>|<<<<<<<<<<<<<<<|")

	cer, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Println(err)
		return
	}

	conf := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", ":"+port, conf)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn, key)
	}
}

func handleConnection(conn net.Conn, key string) {
	log.Println("[+]", conn.RemoteAddr())

	var handshake Handshake

	//读取客户端发送的key
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		log.Println(n, err)
		conn.Close()
		return
	}

	//验证key
	if string(buf[:n]) == key {
		_, err = conn.Write([]byte{0})
		if err != nil {
			log.Println(err)
			conn.Close()
			return
		}
	} else {
		log.Println(conn.RemoteAddr(), "验证失败，对方所使用的key：", string(buf[:n]))
		_, err = conn.Write([]byte{1})
		if err != nil {
			log.Println(err)
			conn.Close()
			return
		}
		conn.Close()
		return
	}

	//读取客户端发送数据
	buf = make([]byte, 100)
	n, err = conn.Read(buf)
	if err != nil {
		log.Println(n, err)
		conn.Close()
		return
	}

	//对数据解码
	err = decode(buf[:n], &handshake)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	log.Println(conn.RemoteAddr(), "=="+handshake.Reqtype+"=>", handshake.Url)

	//connect
	pconn, err := net.Dial(handshake.Reqtype, handshake.Url)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	go func(in net.Conn, out net.Conn, host, reqtype string) {
		io.Copy(in, out)
		in.Close()
		out.Close()
		log.Println(in.RemoteAddr(), "=="+reqtype+"=>", host, "[√]")
	}(conn, pconn, handshake.Url, handshake.Reqtype)

	go func(in net.Conn, out net.Conn, host, reqtype string) {
		io.Copy(in, out)
		in.Close()
		out.Close()
		log.Println(out.RemoteAddr(), "<="+reqtype+"==", host, "[√]")
	}(pconn, conn, handshake.Url, handshake.Reqtype)
}

func decode(data []byte, to interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(to)
}

type Handshake struct {
	Url     string
	Reqtype string
}
