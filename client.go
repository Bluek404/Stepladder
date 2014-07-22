package main

import (
	"bytes"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"github.com/Unknwon/goconfig"
	"io"
	"log"
	"net"
)

func main() {
	log.SetFlags(log.Lshortfile)

	config, err := goconfig.LoadConfigFile("client.ini")
	if err != nil {
		log.Println(err)
		return
	}

	var (
		port       = config.MustValue("client", "port", "7071")
		key        = config.MustValue("client", "key", "EbzHvwg8BVYz9Rv3")
		serverHost = config.MustValue("server", "host", "127.0.0.1")
		serverPort = config.MustValue("server", "port", "8081")
	)

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Println(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn, key, serverHost, serverPort)
	}
}

func handleConnection(conn net.Conn, key, host, port string) {
	//defer conn.Close()
	log.Println("remote addr:", conn.RemoteAddr())

	var (
		reqhello reqHello
		ansecho  ansEcho
		reqmsg   ReqMsg
		ansmsg   ansMsg
	)

	//recv hello
	var err error
	err = reqhello.read(conn)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}
	reqhello.print()

	//send echo
	ansecho.gen(0)
	ansecho.write(conn)
	ansecho.print()

	//recv request
	err = reqmsg.read(conn)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}
	reqmsg.print()

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	pconn, err := tls.Dial("tcp", host+":"+port, conf)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	reqmsg.Key = key

	//编码
	enc, err := encode(&reqmsg)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	_, err = pconn.Write(enc)
	if err != nil {
		log.Println(err)
		conn.Close()
		pconn.Close()
		return
	}

	//读取服务端返回信息
	buf := make([]byte, 1)
	n, err := pconn.Read(buf)
	if err != nil {
		log.Println(n, err)
		conn.Close()
		pconn.Close()
		return
	}
	if buf[0] != 0 {
		log.Println("服务端验证失败")
		conn.Close()
		pconn.Close()
		return
	}

	//success
	ansmsg.gen(0)
	ansmsg.write(conn)
	ansmsg.print()

	pipe(pconn, conn)
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

func recv(buf []byte, m int, conn net.Conn) (n int, err error) {
	for nn := 0; n < m; {
		nn, err = conn.Read(buf[n:m])
		if err != nil && io.EOF != err {
			return
		}
		n += nn
	}
	return
}

type reqHello struct {
	ver      uint8
	nmethods uint8
	methods  [255]uint8
}

func (msg *reqHello) read(conn net.Conn) (err error) {
	_, err = recv(msg.methods[:2], 2, conn)
	if err != nil {
		return
	}
	msg.ver, msg.nmethods = msg.methods[0], msg.methods[1]
	_, err = recv(msg.methods[:], int(msg.nmethods), conn)
	if err != nil {
		return
	}
	return
}
func (msg *reqHello) print() {
	log.Println("************")
	log.Println("get reqHello msg:")
	log.Println("ver:", msg.ver, " nmethods:", msg.nmethods, " methods:", msg.methods[:msg.nmethods])
	log.Println("************")
}

type ansEcho struct {
	ver    uint8
	method uint8
	buf    [2]uint8
}

func (msg *ansEcho) gen(t uint8) {
	msg.ver, msg.method = 5, t
	msg.buf[0], msg.buf[1] = 5, t
}
func (msg *ansEcho) write(conn net.Conn) {
	conn.Write(msg.buf[:])
}
func (msg *ansEcho) print() {
	log.Println("------------------")
	log.Println("send ansEcho msg:")
	log.Println("ver:", msg.ver, " method:", msg.method)
	log.Println("------------------")
}

type ReqMsg struct {
	ver       uint8     // socks v5: 0x05
	cmd       uint8     // CONNECT: 0x01, BIND:0x02, UDP ASSOCIATE: 0x03
	rsv       uint8     //RESERVED
	atyp      uint8     //IP V4 addr: 0x01, DOMANNAME: 0x03, IP V6 addr: 0x04
	dst_addr  [255]byte //
	dst_port  [2]uint8  //
	dst_port2 uint16    //

	Reqtype string
	Url     string
	Key     string
}

func (msg *ReqMsg) read(conn net.Conn) (err error) {
	buf := make([]byte, 4)
	_, err = recv(buf, 4, conn)
	if err != nil {
		return
	}

	msg.ver, msg.cmd, msg.rsv, msg.atyp = buf[0], buf[1], buf[2], buf[3]

	if 5 != msg.ver || 0 != msg.rsv {
		log.Println("Request Message VER or RSV error!")
		return
	}
	switch msg.atyp {
	case 1: //ip v4
		_, err = recv(msg.dst_addr[:], 4, conn)
	case 4:
		_, err = recv(msg.dst_addr[:], 16, conn)
	case 3:
		_, err = recv(msg.dst_addr[:1], 1, conn)
		_, err = recv(msg.dst_addr[1:], int(msg.dst_addr[0]), conn)
	}
	if err != nil {
		return
	}
	_, err = recv(msg.dst_port[:], 2, conn)
	if err != nil {
		return
	}

	msg.dst_port2 = (uint16(msg.dst_port[0]) << 8) + uint16(msg.dst_port[1])

	switch msg.cmd {
	case 1:
		msg.Reqtype = "tcp"
	case 2:
		log.Println("BIND")
	case 3:
		msg.Reqtype = "udp"
	}
	switch msg.atyp {
	case 1: // ipv4
		msg.Url = fmt.Sprintf("%d.%d.%d.%d:%d", msg.dst_addr[0], msg.dst_addr[1], msg.dst_addr[2], msg.dst_addr[3], msg.dst_port2)
	case 3: //DOMANNAME
		msg.Url = string(msg.dst_addr[1 : 1+msg.dst_addr[0]])
		msg.Url += fmt.Sprintf(":%d", msg.dst_port2)
	case 4: //ipv6
		log.Println("IPV6")
	}
	return
}
func (msg *ReqMsg) print() {
	log.Println("---***-----****----***---")
	log.Println("get reqmsg:")
	log.Println("ver:", msg.ver, " cmd:", msg.cmd, " rsv:", msg.rsv, " atyp", msg.atyp, " dst_addr:", msg.Url)
	log.Println("---***-----****----***---")
}

type ansMsg struct {
	ver  uint8
	rep  uint8
	rsv  uint8
	atyp uint8
	buf  [300]uint8
	mlen uint16
}

func (msg *ansMsg) gen(rep uint8) {
	msg.ver = 5
	msg.rep = rep //rfc1928
	msg.rsv = 0
	msg.atyp = 1

	msg.buf[0], msg.buf[1], msg.buf[2], msg.buf[3] = msg.ver, msg.rep, msg.rsv, msg.atyp
	for i := 5; i < 11; i++ {
		msg.buf[i] = 0
	}
	msg.mlen = 10
}
func (msg *ansMsg) write(conn net.Conn) {
	conn.Write(msg.buf[:msg.mlen])
}
func (msg *ansMsg) print() {
	log.Println("***-----****----***---***")
	log.Println("send ans msg:")
	log.Println(msg.buf[:msg.mlen])
	log.Println("***-----****----***---***")
}
