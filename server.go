package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type event struct {
	RunID        string    `json:"run_id"`
	Sequence     uint64    `json:"sequence"`
	ConnectionID string    `json:"connection_id"`
	Type         string    `json:"type"`
	Time         time.Time `json:"time"`
	Data         any       `json:"data"`
}
type eventStore struct {
	runID    string
	mu       sync.Mutex
	encoder  *json.Encoder
	events   []event
	active   map[string]net.Conn
	closed   bool
	written  int64
	counter  atomic.Uint64
	sequence uint64
	err      error
}

func (s *eventStore) nextID() string { return fmt.Sprintf("conn-%d", s.counter.Add(1)) }
func (s *eventStore) emit(id, kind string, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.err != nil {
		return
	}
	s.sequence++
	e := event{RunID: s.runID, Sequence: s.sequence, ConnectionID: id, Type: kind, Time: time.Now().UTC(), Data: v}
	b, err := json.Marshal(e)
	if err != nil {
		s.err = err
		return
	}
	limited := s.sequence >= 10000 || s.written+int64(len(b)) > 64<<20-1024
	if limited {
		e.Type = "capture.incomplete"
		e.Data = map[string]string{"reason": "run event or evidence byte limit reached"}
		b, _ = json.Marshal(e)
	}
	if len(s.events) < 10000 {
		s.events = append(s.events, e)
	}
	if s.encoder != nil && s.err == nil {
		s.err = s.encoder.Encode(json.RawMessage(b))
		s.written += int64(len(b) + 1)
	}
	if limited && s.err == nil {
		s.err = fmt.Errorf("capture budget exhausted")
	}
}

type connectionKey struct{}
type Config struct {
	HTTPAddr       string
	TLSAddr        string
	ManagementAddr string
	Output         string
}
type Lab struct {
	store     *eventStore
	servers   []*http.Server
	listeners []net.Listener
	log       *os.File
	Manifest  Manifest
	once      sync.Once
}
type Manifest struct {
	RunID          string         `json:"run_id"`
	StartedAt      time.Time      `json:"started_at"`
	PID            int            `json:"pid"`
	CaptureVersion string         `json:"capture_version"`
	SchemaVersion  int            `json:"schema_version"`
	HTTP           string         `json:"http"`
	HTTPS2         string         `json:"https2"`
	HTTPS          string         `json:"https"`
	Management     string         `json:"management"`
	CAFile         string         `json:"ca_file"`
	Capabilities   map[string]any `json:"capabilities"`
}

func certificates() (tls.Certificate, []byte, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fastls Lab temporary CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &private.PublicKey, private)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serverPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &serverPrivate.PublicKey, private)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: serverPrivate}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}
func Start(config Config) (*Lab, error) {
	if err := os.MkdirAll(config.Output, 0700); err != nil {
		return nil, err
	}
	log, err := os.OpenFile(filepath.Join(config.Output, "events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	lab := &Lab{log: log, store: &eventStore{runID: filepath.Base(config.Output), encoder: json.NewEncoder(log), active: map[string]net.Conn{}}}
	ok := false
	defer func() {
		if !ok {
			lab.Close()
		}
	}()
	cert, ca, err := certificates()
	if err != nil {
		return nil, err
	}
	caFile := filepath.Join(config.Output, "ca.pem")
	if err = os.WriteFile(caFile, ca, 0600); err != nil {
		return nil, err
	}
	capabilities := map[string]any{"tls_client_hello": true, "tls_negotiated": true, "tls_versions": []string{"1.2", "1.3"}, "http1_headers": "first-request-per-connection", "http2": "first-request-frames-and-headers", "http3": false, "ws": true, "wss": true, "ws_compression": false, "ws_h2_h3": false, "scope": "initial diagnostic implementation; not whole-plan acceptance"}
	add := func(addr string, handler http.Handler, secure, observe bool) (string, error) {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return "", err
		}
		lab.listeners = append(lab.listeners, listener)
		var serve net.Listener = listener
		if observe {
			observed := observationListener{Listener: listener, store: lab.store}
			if secure {
				observed.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
			}
			serve = observed
		}
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if observed, ok := c.(*observedConn); ok {
				return context.WithValue(ctx, connectionKey{}, observed)
			}
			return ctx
		}}
		lab.servers = append(lab.servers, server)
		go func() {
			if err := server.Serve(serve); err != nil && err != http.ErrServerClosed {
				lab.store.emit("", "server.error", err.Error())
			}
		}()
		scheme := "http://"
		if secure {
			scheme = "https://"
		}
		return scheme + listener.Addr().String(), nil
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Context().Value(connectionKey{}).(*observedConn)
		if c == nil {
			http.Error(w, "no connection evidence", 500)
			return
		}
		if r.URL.Path == "/ws" {
			lab.websocket(w, r, c)
			return
		}
		if r.URL.Path != "/inspect" {
			http.NotFound(w, r)
			return
		}
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if len(body) > 1<<20 {
			http.Error(w, "body too large", 413)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"connection_id": c.id, "method": r.Method, "path": r.URL.Path, "body_bytes": len(body), "evidence": "events.jsonl; no fingerprint-match claim"})
	})
	httpAddr, err := add(config.HTTPAddr, handler, false, true)
	if err != nil {
		return nil, err
	}
	tlsAddr, err := add(config.TLSAddr, handler, true, true)
	if err != nil {
		return nil, err
	}
	management := http.NewServeMux()
	management.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		lab.store.mu.Lock()
		captureErr := lab.store.err
		lab.store.mu.Unlock()
		if captureErr != nil {
			http.Error(w, "evidence write failed", 500)
			return
		}
		w.Write([]byte("ready\n"))
	})
	management.HandleFunc("/capabilities", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(capabilities)
	})
	management.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		lab.store.mu.Lock()
		defer lab.store.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(lab.store.events)
	})
	managementAddr, err := add(config.ManagementAddr, management, false, false)
	if err != nil {
		return nil, err
	}
	h2Addr, err := lab.startHTTP2(cert)
	if err != nil {
		return nil, err
	}
	lab.Manifest = Manifest{HTTPS2: h2Addr, RunID: lab.store.runID, StartedAt: time.Now().UTC(), PID: os.Getpid(), CaptureVersion: "0.1.0-dev", SchemaVersion: 1, HTTP: httpAddr, HTTPS: tlsAddr, Management: managementAddr, CAFile: caFile, Capabilities: capabilities}
	b, err := json.MarshalIndent(lab.Manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(config.Output, "lab-manifest.json"), b, 0600); err != nil {
		return nil, err
	}
	ok = true
	return lab, nil
}
func (l *Lab) Close() {
	l.once.Do(func() {
		l.store.mu.Lock()
		l.store.closed = true
		active := []net.Conn{}
		for _, c := range l.store.active {
			active = append(active, c)
		}
		l.store.mu.Unlock()
		for _, s := range l.servers {
			s.Close()
		}
		for _, listener := range l.listeners {
			listener.Close()
		}
		for _, c := range active {
			c.Close()
		}
		if l.log != nil {
			l.store.mu.Lock()
			l.log.Close()
			l.store.mu.Unlock()
		}
	})
}
