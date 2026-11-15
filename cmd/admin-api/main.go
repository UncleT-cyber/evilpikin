package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net/http"
	"os"

	"github.com/user/evilpikin/internal/control"
	"github.com/user/evilpikin/internal/log"
	"github.com/user/evilpikin/internal/storage"
	"github.com/user/evilpikin/internal/telemetry"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "admin api bind address (mTLS)")
	certPath := flag.String("cert", "certs/server.pem", "server certificate (PEM)")
	keyPath := flag.String("key", "certs/server.key", "server key (PEM)")
	caPath := flag.String("ca", "certs/ca.pem", "client CA certificate (PEM)")
	dbPath := flag.String("db", "evilpikin.db", "sqlite database path")
	flag.Parse()

	store, err := storage.OpenSQLite(*dbPath)
	if err != nil {
		log.Fatal("storage: %v", err)
	}
	defer store.Close()

	api := control.NewControlAPI(store)
	hub := telemetry.NewHub()

	mux := http.NewServeMux()
	mux.Handle("/api/v1/", api.Handler())
	mux.Handle("/ws", hub.Handler())

	server := &http.Server{
		Addr:    *addr,
		Handler: mux,
	}

	caBytes, err := os.ReadFile(*caPath)
	if err != nil {
		log.Fatal("read client CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		log.Fatal("failed to parse client CA")
	}
	server.TLSConfig = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS12,
	}

	log.Info("admin api (mTLS) listening on %s", *addr)
	if err := server.ListenAndServeTLS(*certPath, *keyPath); err != nil {
		log.Fatal("admin api: %v", err)
	}
}
