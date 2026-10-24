package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHTTP2CaptureCalibratedWithStandardClient(t *testing.T) {
	l := testLab(t)
	pem, err := os.ReadFile(l.Manifest.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("invalid CA")
	}
	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	c := http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", l.Manifest.HTTPS2+"/inspect", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "secret-token")
	req.Header.Add("X-Repeat", "one")
	req.Header.Add("X-Repeat", "two")
	response, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != 200 {
		t.Fatal(response.Proto, response.StatusCode)
	}
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	settings, headers := false, false
	for _, e := range l.store.events {
		if e.Type == "http2.settings" {
			settings = true
		}
		if e.Type == "http2.headers" {
			headers = true
			b, _ := json.Marshal(e.Data)
			if strings.Contains(string(b), "secret-token") || !strings.Contains(string(b), "[redacted]") {
				t.Fatal("H2 authorization leaked")
			}
			if strings.Count(string(b), "x-repeat") != 2 {
				t.Fatal("repeated H2 headers lost")
			}
		}
	}
	if !settings || !headers {
		t.Fatal("standard reference produced no H2 observations")
	}
}
