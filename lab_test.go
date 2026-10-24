package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func testLab(t *testing.T) *Lab {
	t.Helper()
	l, err := Start(Config{HTTPAddr: "127.0.0.1:0", TLSAddr: "127.0.0.1:0", ManagementAddr: "127.0.0.1:0", Output: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return l
}
func trustedConfig(t *testing.T, l *Lab) *tls.Config {
	t.Helper()
	b, err := os.ReadFile(l.Manifest.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		t.Fatal("invalid CA")
	}
	return &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}
func TestRawHeaderOrderAndTLSNegotiation(t *testing.T) {
	l := testLab(t)
	for _, secure := range []bool{false, true} {
		var c net.Conn
		var err error
		if secure {
			config := trustedConfig(t, l)
			config.MaxVersion = tls.VersionTLS12
			c, err = tls.Dial("tcp", strings.TrimPrefix(l.Manifest.HTTPS, "https://"), config)
		} else {
			c, err = net.Dial("tcp", strings.TrimPrefix(l.Manifest.HTTP, "http://"))
		}
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = io.WriteString(c, "GET /inspect HTTP/1.1\r\nHost: localhost\r\nx-Second: 2\r\nX-FIRST: 1\r\nx-Second: again\r\nCookie: secret\r\nConnection: close\r\n\r\n")
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	headers, hellos, negotiated := 0, 0, 0
	for _, event := range l.store.events {
		switch event.Type {
		case "http1.headers":
			obs := event.Data.(httpObservation)
			if obs.Headers[1].Name != "x-Second" || obs.Headers[2].Name != "X-FIRST" || obs.Headers[3].Name != "x-Second" {
				t.Fatal("lost raw casing, order, or repeated header")
			}
			if obs.Headers[4].Value != "[redacted]" {
				t.Fatal("cookie not redacted")
			}
			headers++
		case "tls.client_hello":
			hello := event.Data.(ClientHello)
			if len(hello.CipherSuites) == 0 || len(hello.Extensions) == 0 {
				t.Fatal("empty hello evidence")
			}
			hellos++
		case "tls.negotiated":
			v := event.Data.(map[string]any)
			if v["version"].(uint16) != tls.VersionTLS12 {
				t.Fatal("did not honor TLS1.2 probe")
			}
			negotiated++
		}
	}
	if headers != 2 || hellos != 1 || negotiated != 1 {
		t.Fatalf("headers=%d hellos=%d negotiated=%d", headers, hellos, negotiated)
	}
}

func masked(opcode byte, fin bool, payload string) []byte {
	first := opcode
	if fin {
		first |= 128
	}
	data := []byte{first, 0x80 | byte(len(payload)), 1, 2, 3, 4}
	for i, b := range []byte(payload) {
		data = append(data, b^byte(i%4+1))
	}
	return data
}
func serverFrame(t *testing.T, r *bufio.Reader) (byte, string) {
	t.Helper()
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		t.Fatal(err)
	}
	if h[1]&128 != 0 {
		t.Fatal("server must not mask")
	}
	n := int(h[1] & 127)
	if n >= 126 {
		t.Fatal("fixture expects short server frame")
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		t.Fatal(err)
	}
	return h[0] & 15, string(p)
}
func TestWSAndWSSFramesAndFailure(t *testing.T) {
	l := testLab(t)
	for _, secure := range []bool{false, true} {
		var c net.Conn
		var err error
		if secure {
			c, err = tls.Dial("tcp", strings.TrimPrefix(l.Manifest.HTTPS, "https://"), trustedConfig(t, l))
		} else {
			c, err = net.Dial("tcp", strings.TrimPrefix(l.Manifest.HTTP, "http://"))
		}
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(c)
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 101 || response.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
			t.Fatalf("bad upgrade: %v", response)
		}
		c.Write(masked(1, false, "hel"))
		c.Write(masked(9, true, "ping"))
		op, p := serverFrame(t, reader)
		if op != 10 || p != "ping" {
			t.Fatal("control frame not handled during fragmented message")
		}
		c.Write(masked(0, true, "lo"))
		op, p = serverFrame(t, reader)
		if op != 1 || p != "hello" {
			t.Fatal("fragmented echo differs")
		}
		// A client must mask. Verify the negative probe yields a protocol close.
		c.Write([]byte{0x81, 1, 'x'})
		op, p = serverFrame(t, reader)
		if op != 8 || len(p) < 2 || binary.BigEndian.Uint16([]byte(p)) != 1002 {
			t.Fatal("invalid client frame was not rejected")
		}
		c.Close()
	}
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	accepted, failures := 0, 0
	for _, e := range l.store.events {
		if e.Type == "ws.handshake_accepted" {
			accepted++
		}
		if e.Type == "ws.protocol_error" {
			failures++
		}
	}
	if accepted != 2 || failures != 2 {
		t.Fatalf("WS evidence missing: accepted=%d errors=%d", accepted, failures)
	}
}

func TestManagementAndUntrustedCertificate(t *testing.T) {
	l := testLab(t)
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(client.CloseIdleConnections)
	if response, err := client.Get(l.Manifest.HTTPS + "/inspect"); err == nil {
		response.Body.Close()
		t.Fatal("untrusted certificate accepted")
	}
	response, err := client.Get(l.Manifest.Management + "/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var data map[string]any
	if err = json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatal(err)
	}
	if data["http2"] != "first-request-frames-and-headers" || data["http3"] != false || data["ws_compression"] != false {
		t.Fatal("overstated capabilities")
	}
}

func TestClientHelloRecordFragmentation(t *testing.T) {
	// Independent minimal byte fixture with two suites and two ordered extensions.
	payload := append([]byte{3, 3}, make([]byte, 32)...)
	payload = append(payload, 0, 0, 4, 0x13, 2, 0x13, 1, 1, 0)
	extensions := []byte{0, 10, 0, 4, 0, 2, 0, 29, 0, 43, 0, 3, 2, 3, 4}
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(extensions)))
	payload = append(payload, extensions...)
	handshake := append([]byte{1, 0, 0, byte(len(payload))}, payload...)
	record := func(p []byte) []byte {
		v := []byte{22, 3, 1}
		v = binary.BigEndian.AppendUint16(v, uint16(len(p)))
		return append(v, p...)
	}
	raw := append(record(handshake[:17]), record(handshake[17:])...)
	got, err := clientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.CipherSuites[0] != 0x1302 || got.CipherSuites[1] != 0x1301 || got.Extensions[0].ID != 10 || got.Extensions[1].ID != 43 {
		t.Fatal("lost observed order")
	}
	for i := 0; i < len(raw); i++ {
		if _, err := clientHello(raw[:i]); err == nil {
			t.Fatalf("accepted incomplete capture at %d", i)
		}
	}
}
func TestFrameParserRejectsInvalidEncodings(t *testing.T) {
	for _, b := range [][]byte{{0xc1, 128, 1, 2, 3, 4}, {0x81, 0}, {0x09, 128, 1, 2, 3, 4}, {0x83, 128, 1, 2, 3, 4}, {0x81, 254, 0, 1, 1, 2, 3, 4, 0}} {
		if _, err := readFrame(bytes.NewReader(b)); err == nil {
			t.Fatalf("accepted invalid frame %v", b)
		}
	}
}
func FuzzClientHello(f *testing.F) {
	f.Add([]byte{22, 3, 1, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 128<<10 {
			return
		}
		clientHello(b)
	})
}

func TestCaptureBudgetIsReportedAndBounded(t *testing.T) {
	store := &eventStore{}
	for range 10010 {
		store.emit("fixture", "probe", map[string]string{"value": "small"})
	}
	if len(store.events) != 10000 || store.err == nil || store.events[9999].Type != "capture.incomplete" {
		t.Fatal("budget overflow not represented honestly")
	}
}

func TestCloseReleasesHijackedConnection(t *testing.T) {
	lab := testLab(t)
	c, err := net.Dial("tcp", strings.TrimPrefix(lab.Manifest.HTTP, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	reader := bufio.NewReader(c)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != 101 {
		t.Fatalf("upgrade failed: %v", err)
	}
	lab.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = reader.ReadByte(); err == nil {
		t.Fatal("hijacked socket still open")
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("close did not release hijacked socket")
	}
}
