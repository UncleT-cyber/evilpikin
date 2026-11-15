package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	ca := os.Args[1]
	cert := os.Args[2]
	key := os.Args[3]
	wsURL := os.Args[4]

	caBytes, _ := os.ReadFile(ca)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caBytes)
	cli, _ := tls.LoadX509KeyPair(cert, key)

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cli}},
	}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	fmt.Println("WS CONNECTED; triggering proxy hit...")

	go func() {
		time.Sleep(500 * time.Millisecond)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "test.local",
				InsecureSkipVerify: true,
			},
		}
		c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		resp, err := c.Get("https://127.0.0.1:9443/")
		if err != nil {
			fmt.Println("PROXY ERR:", err)
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Println("PROXY HIT:", resp.Status)
	}()

	conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			fmt.Println("WS DONE:", err)
			return
		}
		fmt.Println("WS EVENT:", string(msg))
	}
}
