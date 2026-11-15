package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/websocket"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8081", "dashboard listen address")
	admin := flag.String("admin", "https://127.0.0.1:8443", "admin-api / control-api base url")
	caPath := flag.String("ca", "certs/ca.pem", "admin-api client CA")
	certPath := flag.String("cert", "certs/client.pem", "admin-api client cert")
	keyPath := flag.String("key", "certs/client.key", "admin-api client key")
	webDir := flag.String("web", "web", "static web directory")
	insecure := flag.Bool("insecure", false, "connect to a plain (non-mTLS) control api (dev mode), e.g. http://127.0.0.1:8080")
	flag.Parse()

	var tlsCfg *tls.Config
	wsScheme := "wss://"
	if *insecure {
		wsScheme = "ws://"
		if !strings.HasPrefix(*admin, "http://") {
			*admin = "http://" + strings.TrimPrefix(*admin, "https://")
		}
	} else {
		caBytes, err := os.ReadFile(*caPath)
		if err != nil {
			log.Fatalf("read CA: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			log.Fatal("parse CA failed")
		}
		cli, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			log.Fatalf("load client cert: %v", err)
		}
		tlsCfg = &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cli}}
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(*webDir)))

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		d := websocket.Dialer{TLSClientConfig: tlsCfg}
		base := strings.TrimPrefix(strings.TrimPrefix(*admin, "https://"), "http://")
		ac, _, err := d.Dial(wsScheme+base+"/ws", nil)
		if err != nil {
			log.Printf("dashboard: dial upstream ws: %v", err)
			return
		}
		defer ac.Close()
		go func() {
			for {
				mt, m, err := ac.ReadMessage()
				if err != nil {
					return
				}
				c.WriteMessage(mt, m)
			}
		}()
		for {
			mt, m, err := c.ReadMessage()
			if err != nil {
				return
			}
			ac.WriteMessage(mt, m)
		}
	})

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		targetURL := *admin + strings.Replace(r.URL.Path, "/api/", "/api/v1/", 1)
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}
		req, err := http.NewRequest(r.Method, targetURL, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Header = r.Header.Clone()
		client := &http.Client{}
		if tlsCfg != nil {
			client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})

	log.Printf("dashboard listening on %s (relaying to %s, insecure=%v)", *addr, *admin, *insecure)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("dashboard: %v", err)
	}
}
