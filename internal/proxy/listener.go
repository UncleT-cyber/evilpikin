package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/user/evilpikin/internal/log"
	"github.com/user/evilpikin/internal/telemetry"
)

type PublicListener struct {
	engine    *Engine
	router    *Router
	httpAddr  string
	httpsAddr string
	httpLn    net.Listener
	httpsLn   net.Listener
	stopped   atomic.Bool
}

func NewPublicListener(engine *Engine, resolver CertResolver, httpAddr, httpsAddr string) *PublicListener {
	if httpAddr == "" {
		httpAddr = ":80"
	}
	if httpsAddr == "" {
		httpsAddr = ":443"
	}
	pl := &PublicListener{
		engine:    engine,
		router:    NewRouter(engine.sessions, resolver),
		httpAddr:  httpAddr,
		httpsAddr: httpsAddr,
	}
	pl.router.SetHandler(func(sni string, conn *tls.Conn) {
		pl.serveConn(sni, conn)
	})
	return pl
}

func (l *PublicListener) Start() error {
	l.stopped.Store(false)
	go l.listenHTTPS()
	go l.listenHTTP()
	return nil
}

func (l *PublicListener) Shutdown() {
	if l.stopped.Swap(true) {
		return
	}
	if l.httpsLn != nil {
		l.httpsLn.Close()
	}
	if l.httpLn != nil {
		l.httpLn.Close()
	}
	log.Info("data plane: listeners shut down")
}

func (l *PublicListener) listenHTTPS() {
	ln, err := net.Listen("tcp", l.httpsAddr)
	if err != nil {
		log.Fatal("public listener https: %v", err)
		return
	}
	l.httpsLn = ln
	log.Info("data plane: public https listener on %s", l.httpsAddr)
	for {
		if l.stopped.Load() {
			return
		}
		conn, err := ln.Accept()
		if err != nil {
			if l.stopped.Load() {
				return
			}
			log.Error("public listener https accept: %v", err)
			continue
		}
		go l.router.HandleIncoming(conn)
	}
}

func (l *PublicListener) listenHTTP() {
	ln, err := net.Listen("tcp", l.httpAddr)
	if err != nil {
		log.Fatal("public listener http: %v", err)
		return
	}
	l.httpLn = ln
	log.Info("data plane: public http listener on %s", l.httpAddr)
	for {
		if l.stopped.Load() {
			return
		}
		conn, err := ln.Accept()
		if err != nil {
			if l.stopped.Load() {
				return
			}
			log.Error("public listener http accept: %v", err)
			continue
		}
		go l.handlePlaintext(conn)
	}
}

func (l *PublicListener) serveConn(sni string, conn *tls.Conn) {
	h, err := l.engine.HandlerFor(sni)
	if err != nil {
		log.Error("data plane: no target for sni=%s remote=%s", sni, conn.RemoteAddr())
		conn.Close()
		return
	}
	if l.engine.telemetryHub != nil {
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		l.engine.telemetryHub.Broadcast(telemetry.Event{
			Type:     telemetry.EventSession,
			TargetID: sni,
			Time:     time.Now(),
			Data:     map[string]string{"sni": sni, "remote": ip},
		})
	}
	srv := &http.Server{Handler: h}
	if err := srv.Serve(&singleConnListener{conn: conn}); err != nil {
		log.Debug("data plane: serve sni=%s: %v", sni, err)
	}
}

type singleConnListener struct {
	conn net.Conn
	done bool
}

func (s *singleConnListener) Accept() (net.Conn, error) {
	if s.done {
		return nil, io.EOF
	}
	s.done = true
	return s.conn, nil
}

func (s *singleConnListener) Close() error { return nil }

func (s *singleConnListener) Addr() net.Addr { return s.conn.LocalAddr() }

func (l *PublicListener) handlePlaintext(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	req := string(buf[:n])
	host := ""
	if idx := strings.Index(req, "Host:"); idx >= 0 {
		line := req[idx:]
		if nl := strings.IndexByte(line, '\r'); nl >= 0 {
			line = line[:nl]
		} else if nl := strings.IndexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			host = strings.TrimSpace(parts[1])
		}
	}
	// Strip any port the client sent and rebuild the URL against the TLS
	// listener's actual port so the upgrade lands on the right endpoint
	// (e.g. http :9080 -> https :9443, not https :9080).
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	tlsPort := "443"
	if _, p, err := net.SplitHostPort(l.httpsAddr); err == nil && p != "" {
		tlsPort = p
	}
	target := "https://" + net.JoinHostPort(host, tlsPort) + "/"
	resp := fmt.Sprintf("HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", target)
	io.WriteString(conn, resp)
}
