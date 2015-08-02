/*
   Copyright 2015 Bluek404 <i@bluek404.net>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/ije/gox/config"
	"io"
	"net"
	"strings"
	"time"
)

const (
	login = iota
	connection
	pacscript
)

func main() {
	etcDir := "/usr/local/etc/fuckgfw/"

	cfg, err := config.New(etcDir + "server.cfg")
	if err != nil {
		fmt.Println("Load config failed:", err)
		return
	}

	cert, err := tls.LoadX509KeyPair(etcDir+"cert.pem", etcDir+"key.pem")
	if err != nil {
		fmt.Println(err)
		return
	}

	ln, err := tls.Listen("tcp", ":"+cfg.String("port", "8080"), &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer ln.Close()

	s := &serve{
		key:     cfg.String("key", "helloworld~"),
		clients: make(map[string]uint),
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		go s.handleConnection(conn)
	}
}

type serve struct {
	key     string
	clients map[string]uint
	keepit  map[string]chan bool
}

func (s *serve) handleConnection(conn net.Conn) {
	fmt.Println("[+]", conn.RemoteAddr())

	var msg Message

	// read client data
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println(n, err)
		conn.Close()
		return
	}

	// decode
	err = gob.NewDecoder(bytes.NewBuffer(buf[:n])).Decode(&msg)
	if err != nil {
		fmt.Println(err)
		conn.Close()
		return
	}

	switch msg.Type {
	case login:
		if msg.Value["key"] == s.key {
			fmt.Println("New Client:", conn.RemoteAddr().String())
			isOK(conn)

			s.clients[getIP(conn.RemoteAddr().String())]++

			defer conn.Close()

			for {
				conn.SetDeadline(time.Now().Add(time.Second * 65))
				buf := make([]byte, 1)
				_, err = conn.Read(buf)
				if err != nil {
					conn.SetDeadline(time.Now().Add(time.Second * 10))
					_, err = conn.Read(buf)
					if err != nil {
						fmt.Println("Client offline:", err)
						s.clients[getIP(conn.RemoteAddr().String())]--
						if s.clients[getIP(conn.RemoteAddr().String())] == 0 {
							delete(s.clients, getIP(conn.RemoteAddr().String()))
						}
						return
					}
				}
				isOK(conn)
			}
		} else {
			fmt.Println(conn.RemoteAddr(), "incorrect key:", msg.Value["key"])
			isntOK(conn)
			return
		}
	case pacscript:
		conn.Write([]byte("proxy.pac"))

	case connection:
		err := s.clientOnClientsList(conn)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(conn.RemoteAddr(), "<="+msg.Value["reqtype"]+"=>", msg.Value["url"], "[+]")

		// dial
		pconn, err := net.Dial(msg.Value["reqtype"], msg.Value["url"])
		if err != nil {
			fmt.Println(err)
			fmt.Println(conn.RemoteAddr(), "=="+msg.Value["reqtype"]+"=>", msg.Value["url"], "[×]")
			fmt.Println(conn.RemoteAddr(), "<="+msg.Value["reqtype"]+"==", msg.Value["url"], "[×]")
			conn.Write([]byte{3})
			conn.Close()
			return
		}
		conn.Write([]byte{0})

		go func() {
			io.Copy(conn, pconn)
			conn.Close()
			pconn.Close()
			fmt.Println(conn.RemoteAddr(), "=="+msg.Value["reqtype"]+"=>", msg.Value["url"], "[√]")
		}()
		go func() {
			io.Copy(pconn, conn)
			pconn.Close()
			conn.Close()
			fmt.Println(conn.RemoteAddr(), "<="+msg.Value["reqtype"]+"==", msg.Value["url"], "[√]")
		}()
	default:
		fmt.Println("Unknow requert type:", msg.Type)
	}
}

func getIP(ip string) string {
	if strings.Contains(ip, ":") {
		ip = ip[:strings.Index(ip, ":")]
	}
	return ip
}

func (s *serve) clientOnClientsList(conn net.Conn) error {
	_, ok := s.clients[getIP(conn.RemoteAddr().String())]
	if !ok {
		isntOK(conn)
		return errors.New("Illegal connection:" + conn.RemoteAddr().String())
	}
	isOK(conn)
	return nil
}

func isOK(conn net.Conn) {
	_, err := conn.Write([]byte{0})
	if err != nil {
		fmt.Println(err)
		conn.Close()
	}
}

func isntOK(conn net.Conn) {
	_, err := conn.Write([]byte{1})
	if err != nil {
		fmt.Println(err)
	}
	conn.Close()
}

type Message struct {
	Type  int
	Value map[string]string
}
