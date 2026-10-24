package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/http2/hpack"
)

// This bounded diagnostic receiver observes frames independently of Fastls and
// fhttp. It supports the first request per connection, not a general H2 server.
func (l *Lab) startHTTP2(cert tls.Certificate) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	l.listeners = append(l.listeners, ln)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go l.serveHTTP2(raw, cert)
		}
	}()
	return "https://" + ln.Addr().String(), nil
}
func (l *Lab) serveHTTP2(raw net.Conn, cert tls.Certificate) {
	id := l.store.nextID()
	l.store.mu.Lock()
	if l.store.closed {
		l.store.mu.Unlock()
		raw.Close()
		return
	}
	l.store.active[id] = raw
	l.store.mu.Unlock()
	defer func() { raw.Close(); l.store.mu.Lock(); delete(l.store.active, id); l.store.mu.Unlock() }()
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	capture := &captureConn{Conn: raw, capture: func(h ClientHello) { l.store.emit(id, "tls.client_hello", h) }}
	c := tls.Server(capture, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}})
	defer c.Close()
	if err := c.Handshake(); err != nil {
		l.store.emit(id, "http2.error", err.Error())
		return
	}
	state := c.ConnectionState()
	l.store.emit(id, "tls.negotiated", map[string]any{"version": state.Version, "cipher_suite": state.CipherSuite, "alpn": state.NegotiatedProtocol, "resumed": state.DidResume})
	preface := make([]byte, 24)
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		l.store.emit(id, "http2.error", "invalid preface")
		return
	}
	write := func(typ, flags byte, stream uint32, payload []byte) error {
		h := make([]byte, 9)
		h[0] = byte(len(payload) >> 16)
		h[1] = byte(len(payload) >> 8)
		h[2] = byte(len(payload))
		h[3] = typ
		h[4] = flags
		binary.BigEndian.PutUint32(h[5:], stream)
		if _, err := c.Write(append(h, payload...)); err != nil {
			return err
		}
		return nil
	}
	if err := write(4, 0, 0, nil); err != nil {
		return
	}
	decoder := hpack.NewDecoder(65536, nil)
	decoder.SetMaxStringLength(64 << 10)
	var block []byte
	var blockStream uint32
	completed := false
	finish := func(stream uint32) bool {
		fields, err := decoder.DecodeFull(block)
		if err != nil {
			l.store.emit(id, "http2.error", err.Error())
			return false
		}
		headers := []field{}
		for _, h := range fields {
			v := h.Value
			if strings.EqualFold(h.Name, "cookie") || strings.EqualFold(h.Name, "authorization") || strings.EqualFold(h.Name, "proxy-authorization") {
				v = "[redacted]"
			}
			headers = append(headers, field{Name: h.Name, Value: v})
		}
		l.store.emit(id, "http2.headers", map[string]any{"stream_id": stream, "headers": headers, "scope": "first-request-per-connection"})
		// HPACK indexed :status=200, END_HEADERS and END_STREAM.
		return write(1, 5, stream, []byte{0x88}) == nil
	}
	for count := 0; count < 256; count++ {
		h := make([]byte, 9)
		if _, err := io.ReadFull(c, h); err != nil {
			return
		}
		n := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
		if n > 64<<10 {
			l.store.emit(id, "capture.incomplete", map[string]string{"reason": "HTTP2 frame budget exceeded"})
			return
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(c, p); err != nil {
			return
		}
		typ, flags, stream := h[3], h[4], binary.BigEndian.Uint32(h[5:])&0x7fffffff
		if blockStream != 0 && typ != 9 {
			l.store.emit(id, "http2.error", "interleaved header continuation")
			return
		}
		switch typ {
		case 4:
			if flags&1 != 0 {
				continue
			}
			if stream != 0 || n%6 != 0 {
				return
			}
			settings := []map[string]any{}
			for i := 0; i < n; i += 6 {
				settings = append(settings, map[string]any{"id": binary.BigEndian.Uint16(p[i:]), "value": binary.BigEndian.Uint32(p[i+2:])})
			}
			l.store.emit(id, "http2.settings", settings)
			if err := write(4, 1, 0, nil); err != nil {
				return
			}
		case 8:
			if n != 4 {
				return
			}
			l.store.emit(id, "http2.window_update", map[string]any{"stream_id": stream, "increment": binary.BigEndian.Uint32(p) & 0x7fffffff})
		case 2:
			if n != 5 {
				return
			}
			l.store.emit(id, "http2.priority", map[string]any{"stream_id": stream, "dependency": binary.BigEndian.Uint32(p) & 0x7fffffff, "exclusive": p[0]&128 != 0, "weight": uint16(p[4]) + 1})
		case 1, 9:
			if completed {
				continue
			}
			if stream == 0 {
				return
			}
			if typ == 1 {
				if blockStream != 0 {
					return
				}
				block = nil
				if flags&8 != 0 {
					if len(p) == 0 || int(p[0])+1 > len(p) {
						return
					}
					p = p[1 : len(p)-int(p[0])]
				}
				if flags&32 != 0 {
					if len(p) < 5 {
						return
					}
					l.store.emit(id, "http2.header_priority", map[string]any{"stream_id": stream, "dependency": binary.BigEndian.Uint32(p) & 0x7fffffff, "exclusive": p[0]&128 != 0, "weight": uint16(p[4]) + 1})
					p = p[5:]
				}
			} else if blockStream != stream {
				return
			}
			block = append(block, p...)
			if len(block) > 64<<10 {
				return
			}
			if flags&4 != 0 {
				if !finish(stream) {
					return
				}
				block = nil
				blockStream = 0
				completed = true
				// Drain the peer's queued SETTINGS ACK/WINDOW_UPDATE after a
				// graceful GOAWAY. Closing with unread TCP data can reset a
				// response before the client receives its final HEADERS.
				payload := make([]byte, 8)
				binary.BigEndian.PutUint32(payload, stream)
				if err := write(7, 0, 0, payload); err != nil {
					return
				}
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				continue
			}
			blockStream = stream
		case 6:
			if flags&1 == 0 && n == 8 {
				if err := write(6, 1, 0, p); err != nil {
					return
				}
			}
		case 7:
			return
		default:
			l.store.emit(id, "http2.frame", map[string]any{"type": typ, "flags": flags, "stream_id": stream, "length": n})
		}
	}
	l.store.emit(id, "capture.incomplete", map[string]string{"reason": fmt.Sprint("HTTP2 frame limit")})
}
