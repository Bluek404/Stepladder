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
	if err == io.EOF { //如果收到空数据就直接关闭
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
		log.Println(conn.RemoteAddr(), "验证失败")
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
	go resend(a, b)
	go resend(b, a)
}

func resend(in net.Conn, out net.Conn) {
	_, err := io.Copy(in, out)
	if err != nil {
		log.Println(err)
		in.Close()
		out.Close()
		return
	}
}

type ReqMsg struct {
	Reqtype string
	Url     string
	Key     string
}
