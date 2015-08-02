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
	"crypto/x509"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/ije/gox/config"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"
)

const (
	verSocks5 = 0x05

	atypIPv4Address = 0x01
	atypDomainName  = 0x03
	atypIPv6Address = 0x04

	reqtypeTCP  = 0x01
	reqtypeBIND = 0x02
	reqtypeUDP  = 0x03
)

const (
	login = iota
	connection
	pacscript
)

var (
	reLogin            bool
	heartbeatGoroutine int
)

func main() {
	etcDir := "/usr/local/etc/fuckgfw/"

	rootPEM, err := ioutil.ReadFile(etcDir + "cert.pem")
	if err != nil {
		fmt.Println("read cert.pem filed:", err)
		return
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		fmt.Println("Incorrect cert.pem")
		return
	}

	cfg, err := config.New(etcDir + "client.cfg")
	if err != nil {
		fmt.Println("Load config failed:", err)
		return
	}

	socksListener, err := net.Listen("tcp", ":"+cfg.String("port", "8087"))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer socksListener.Close()

	s := &serve{
		server: cfg.String("server", "127.0.0.1") + ":" + cfg.String("port", "8080"),
		key:    cfg.String("key", "helloworld~"),
		conf: &tls.Config{
			RootCAs: roots,
		},
	}

	if err = s.handshake(); err != nil {
		fmt.Println("Connect to server failed:", err)
		return
	}
	fmt.Println("Conected.")

	// pac
	pconn, _, err := s.send(&Message{
		Type:  pacscript,
		Value: nil,
	})
	if err != nil {
		fmt.Println("Connect to server failed:", err)
	}
	defer pconn.Close()

	if pacScriptData, err := ioutil.ReadAll(pconn); err == nil && len(pacScriptData) > 0 {
		go func() {
			pacListener, err := net.Listen("tcp", ":"+cfg.String("pacPort", "8086"))
			if err != nil {
				fmt.Println(err)
				return
			}
			defer pacListener.Close()
			http.Serve(pacListener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/proxy.pac" {
					w.Header().Set("Server", "fuckgfw-client")
					w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
					w.Header().Set("Content-Length", strconv.Itoa(len(pacScriptData)))
					w.Write(pacScriptData)
				} else {
					http.Error(w, "Page Not Found", 404)
				}
			}))
		}()
	}

	for {
		conn, err := socksListener.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		go s.handleConnection(conn)
	}
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

type serve struct {
	server string
	key    string
	conf   *tls.Config
}

func (s *serve) handshake() error {
	pconn, ok, err := s.send(&Message{
		Type:  login,
		Value: map[string]string{"key": s.key},
	})
	if err != nil {
		return err
	}

	if !ok {
		return errors.New("authentication failed, check the key")
	}

	go func() {
		heartbeatGoroutine++
		defer func() {
			heartbeatGoroutine--
		}()

		for {
			time.Sleep(time.Second * 60)
			_, err := pconn.Write([]byte{0})
			if err != nil {
				if heartbeatGoroutine > 1 {
					return
				} else {
					// try again
					_, err := pconn.Write([]byte{0})
					if err != nil {
						pconn.Close()
						s.reLogin()
						return
					}
				}
			}
		}
	}()
	return nil
}

func (s *serve) send(handshake *Message) (net.Conn, bool, error) {
	// make connection
	pconn, err := tls.Dial("tcp", s.server, s.conf)
	if err != nil {
		return nil, false, err
	}

	// encode
	enc, err := encode(handshake)
	if err != nil {
		pconn.Close()
		return nil, false, err
	}

	// send data
	_, err = pconn.Write(enc)
	if err != nil {
		pconn.Close()
		return nil, false, err
	}

	// read server response data
	buf := make([]byte, 1)
	_, err = pconn.Read(buf)
	if err != nil {
		pconn.Close()
		return nil, false, err
	}

	// check server response status
	if buf[0] != 0 {
		return pconn, false, nil
	}

	return pconn, true, nil
}

func (s *serve) handleConnection(conn net.Conn) {
	fmt.Println("[+]", conn.RemoteAddr())

	// socks5 hand, refer to RFC1928
	var buf = make([]byte, 1+1+255)
	_, err := conn.Read(buf)
	if err != nil {
		fmt.Println(err)
		conn.Close()
		return
	}
	if buf[0] != verSocks5 {
		fmt.Println("Need socks 5, but", buf[0])
		return
	}

	// Send METHOD seletion information
	_, err = conn.Write([]byte{5, 0})
	if err != nil {
		fmt.Println(err)
		conn.Close()
		return
	}

	// Receiving client information
	buf = make([]byte, 4)
	_, err = conn.Read(buf)
	if err != nil {
		fmt.Println(err)
		conn.Close()
		return
	}

	// Determine protocol
	var reqType string
	switch buf[1] {
	case reqtypeTCP:
		reqType = "tcp"
	case reqtypeBIND:
		fmt.Println("BIND")
	case reqtypeUDP:
		reqType = "udp"
	}

	// Get target host
	var host string
	switch buf[3] {
	case atypIPv4Address:
		buf = make([]byte, 4)
		_, err = conn.Read(buf)
		if err != nil {
			fmt.Println(err)
			conn.Close()
			return
		}
		host = net.IP(buf).String()
	case atypIPv6Address:
		buf = make([]byte, 16)
		_, err = conn.Read(buf)
		if err != nil {
			fmt.Println(err)
			conn.Close()
			return
		}
		host = net.IP(buf).String()
	case atypDomainName:
		buf = make([]byte, 1)
		_, err = conn.Read(buf)
		if err != nil {
			fmt.Println(err)
			conn.Close()
			return
		}
		buf = make([]byte, buf[0])
		_, err = conn.Read(buf)
		if err != nil {
			fmt.Println(err)
			conn.Close()
			return
		}
		host = string(buf)
	}

	// Get port
	var port uint16
	err = binary.Read(io.Reader(conn), binary.BigEndian, &port)
	if err != nil {
		fmt.Println(err)
		conn.Close()
		return
	}
	host += ":" + strconv.Itoa(int(port))

	fmt.Println(conn.RemoteAddr(), "<="+reqType+"=>", host, "[+]")

	// Make connection
	pconn, ok, err := s.send(&Message{
		Type:  connection,
		Value: map[string]string{"reqtype": reqType, "url": host},
	})
	if err != nil {
		fmt.Println("Connect to server failed:", err)
		conn.Close()
		return
	}

	// Check server status
	if !ok {
		fmt.Println("Authentication failed")
		pconn.Close()
		conn.Close()
		s.reLogin()
		return
	}

	// Get server status
	buf = make([]byte, 1)
	_, err = pconn.Read(buf)
	if err != nil {
		fmt.Println(err)
		conn.Close()
		return
	}
	code := buf[0]

	// Response message
	_, err = conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		fmt.Println(err)
		conn.Close()
		return
	}

	if code != 0 {
		fmt.Println(conn.RemoteAddr(), "=="+reqType+"=>", host, "[×]")
		fmt.Println(conn.RemoteAddr(), "<="+reqType+"==", host, "[×]")
		return
	}

	go func() {
		io.Copy(conn, pconn)
		conn.Close()
		pconn.Close()
		fmt.Println(conn.RemoteAddr(), "=="+reqType+"=>", host, "[√]")
	}()

	go func() {
		io.Copy(pconn, conn)
		conn.Close()
		pconn.Close()
		fmt.Println(conn.RemoteAddr(), "<="+reqType+"==", host, "[√]")
	}()
}

func (s *serve) reLogin() {
	if !reLogin {
		reLogin = true
		fmt.Println("Relogin...")
		if err := s.handshake(); err != nil {
			fmt.Println("Relogin failed:", err)
			reLogin = false
			return
		}
		fmt.Println("Relogined!")
		reLogin = false
	}
}

type Message struct {
	Type  int
	Value map[string]string
}
