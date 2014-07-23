package main

import (
	"bytes"
	"crypto/tls"
	"encoding/gob"
	"github.com/Unknwon/goconfig"
	"io"
	"log"
	"net"
	"sync"
)

const (
	version = "0.1.5"
)

func main() {
	log.SetFlags(log.Lshortfile)

	cfg, err := goconfig.LoadConfigFile("server.ini")
	if err != nil {
		log.Println(err)
		return
	}

	var (
		key  = cfg.MustValue("client", "key", "EbzHvwg8BVYz9Rv3")
		port = cfg.MustValue("server", "port", "8081")
	)

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

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", ":"+port, config)
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
	log.Println(conn.RemoteAddr())

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
		log.Println(conn.RemoteAddr(), "验证失败，对方所使用的key：", handshake.Key)
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

	log.Println(conn.RemoteAddr(), handshake.Reqtype, handshake.Url)

	//connect
	pconn, err := net.Dial(handshake.Reqtype, handshake.Url)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	var wg sync.WaitGroup

	wg.Add(2)
	go resend(wg, conn, pconn)
	go resend(wg, pconn, conn)
	wg.Wait()
}

func decode(data []byte, to interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(to)
}

func resend(wg sync.WaitGroup, in net.Conn, out net.Conn) {
	defer wg.Done()
	_, err := io.Copy(in, out)
	if err != nil {
		log.Println(err)
	}
}

type Handshake struct {
	Key     string
	Url     string
	Reqtype string
}
