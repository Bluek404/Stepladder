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
	version = "0.1.3"
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
	log.Println("remote addr:", conn.RemoteAddr())

	var reqmsg ReqMsg

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		log.Println(n, err)
		conn.Close()
		return
	}

	//对数据解码
	err = decode(buf[:n], &reqmsg)
	if err == io.ErrUnexpectedEOF { //忽略空数据
		conn.Close()
		return
	}
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	log.Println(conn.RemoteAddr(), reqmsg.Reqtype, reqmsg.Url)

	//验证key
	if reqmsg.Key == key {
		_, err = conn.Write([]byte{0})
		if err != nil {
			log.Println(err)
			conn.Close()
			return
		}
	} else {
		log.Println(conn.RemoteAddr(), "验证失败，对方所使用的key：", reqmsg.Key)
		_, err = conn.Write([]byte{1})
		if err != nil {
			log.Println(err)
			conn.Close()
			return
		}
		conn.Close()
		return
	}

	//connect
	pconn, err := net.Dial(reqmsg.Reqtype, reqmsg.Url)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	pipe(conn, pconn)
}

func decode(data []byte, to interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(to)
}

func pipe(a net.Conn, b net.Conn) {
	cha := make(chan int, 10)
	chb := make(chan int, 10)
	go resend(a, b, cha, chb)
	go resend(b, a, chb, cha)
}

func resend(in net.Conn, out net.Conn, chin, chout chan int) {
	io.Copy(in, out)

	log.Println("等待断开", in.RemoteAddr(), "到", out.RemoteAddr(), "链接")
	chout <- 0
	<-chin
	log.Println(in.RemoteAddr(), "到", out.RemoteAddr(), "链接的已断开")
	in.Close()
	out.Close()
}

type ReqMsg struct {
	Reqtype string
	Url     string
	Key     string
}
