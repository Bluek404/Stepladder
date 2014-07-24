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
	version = "0.1.6"
)

func main() {
	//log.SetFlags(log.Lshortfile)//debug时开启

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
			return
		}
		go handleConnection(conn, key)
	}
}

func handleConnection(conn net.Conn, key string) {
	defer conn.Close()

	log.Println("[+]", conn.RemoteAddr())

	var handshake Handshake

	//读取客户端发送的key
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		log.Println(n, err)
		return
	}

	//验证key
	if string(buf[:n]) == key {
		_, err = conn.Write([]byte{0})
		if err != nil {
			log.Println(err)
			return
		}
	} else {
		log.Println(conn.RemoteAddr(), "验证失败，对方所使用的key：", string(buf[:n]))
		_, err = conn.Write([]byte{1})
		if err != nil {
			log.Println(err)
			return
		}
		return
	}

	//读取客户端发送数据
	buf = make([]byte, 100)
	n, err = conn.Read(buf)
	if err != nil {
		log.Println(n, err)
		return
	}

	//对数据解码
	err = decode(buf[:n], &handshake)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println(conn.RemoteAddr(), "=="+handshake.Reqtype+"=>", handshake.Url)

	//connect
	pconn, err := net.Dial(handshake.Reqtype, handshake.Url)
	if err != nil {
		log.Println(err)
		return
	}
	defer pconn.Close()

	var wg sync.WaitGroup

	wg.Add(1)
	go func(wg sync.WaitGroup, in net.Conn, out net.Conn, host, reqtype string) {
		defer wg.Done()
		io.Copy(in, out)
		log.Println(in.RemoteAddr(), "=="+reqtype+"=>", host, "[√]")
	}(wg, conn, pconn, handshake.Url, handshake.Reqtype)

	func(wg sync.WaitGroup, in net.Conn, out net.Conn, host, reqtype string) {
		defer wg.Done()
		io.Copy(in, out)
		log.Println(out.RemoteAddr(), "<="+reqtype+"==", host, "[√]")
	}(wg, pconn, conn, handshake.Url, handshake.Reqtype)
	wg.Wait()
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
