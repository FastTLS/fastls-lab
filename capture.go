package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
)

type ClientHello struct {
	RecordVersion uint16           `json:"record_version"`
	LegacyVersion uint16           `json:"legacy_version"`
	CipherSuites  []uint16         `json:"cipher_suites"`
	Extensions    []HelloExtension `json:"extensions"`
}
type HelloExtension struct {
	ID             uint16   `json:"id"`
	PayloadHex     string   `json:"payload_hex"`
	KeyShareGroups []uint16 `json:"key_share_groups,omitempty"`
}
type field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type httpObservation struct {
	RequestLine string  `json:"request_line"`
	Headers     []field `json:"headers"`
	Scope       string  `json:"scope"`
}

// clientHello handles both fragmented handshake records and multiple records per read.
// The encrypted remainder and key material are never exported.
func clientHello(raw []byte) (ClientHello, error) {
	var result ClientHello
	var handshake []byte
	for len(raw) >= 5 {
		if result.RecordVersion == 0 {
			result.RecordVersion = binary.BigEndian.Uint16(raw[1:3])
		}
		n := int(binary.BigEndian.Uint16(raw[3:5]))
		if len(raw) < 5+n {
			return result, fmt.Errorf("incomplete TLS record")
		}
		if raw[0] != 22 {
			return result, fmt.Errorf("expected handshake record")
		}
		handshake = append(handshake, raw[5:5+n]...)
		raw = raw[5+n:]
		if len(handshake) >= 4 {
			size := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if handshake[0] != 1 {
				return result, fmt.Errorf("expected ClientHello")
			}
			if len(handshake) >= 4+size {
				return parseHello(result, handshake[4:4+size])
			}
		}
	}
	return result, fmt.Errorf("incomplete ClientHello")
}
func parseHello(result ClientHello, p []byte) (ClientHello, error) {
	take := func(n int) ([]byte, error) {
		if n > len(p) {
			return nil, fmt.Errorf("short ClientHello")
		}
		v := p[:n]
		p = p[n:]
		return v, nil
	}
	fixed, err := take(34)
	if err != nil {
		return result, err
	}
	result.LegacyVersion = binary.BigEndian.Uint16(fixed)
	n, err := take(1)
	if err != nil {
		return result, err
	}
	if _, err = take(int(n[0])); err != nil {
		return result, err
	}
	count, err := take(2)
	if err != nil {
		return result, err
	}
	nCipher := int(binary.BigEndian.Uint16(count))
	ciphers, err := take(nCipher)
	if err != nil || nCipher%2 != 0 {
		return result, fmt.Errorf("invalid cipher vector")
	}
	for len(ciphers) > 0 {
		result.CipherSuites = append(result.CipherSuites, binary.BigEndian.Uint16(ciphers))
		ciphers = ciphers[2:]
	}
	n, err = take(1)
	if err != nil {
		return result, err
	}
	if _, err = take(int(n[0])); err != nil {
		return result, err
	}
	if len(p) == 0 {
		return result, nil
	}
	count, err = take(2)
	if err != nil {
		return result, err
	}
	if int(binary.BigEndian.Uint16(count)) != len(p) {
		return result, fmt.Errorf("invalid extensions vector")
	}
	for len(p) > 0 {
		h, err := take(4)
		if err != nil {
			return result, err
		}
		v, err := take(int(binary.BigEndian.Uint16(h[2:])))
		if err != nil {
			return result, err
		}
		id := binary.BigEndian.Uint16(h)
		// PSK/binder and key_share bytes are connection-specific material, not stable profile fields.
		payload := ""
		if id != 41 && id != 51 {
			payload = hex.EncodeToString(v)
		}
		extension := HelloExtension{ID: id, PayloadHex: payload}
		if id == 51 && len(v) >= 2 {
			entries := v[2:]
			if int(binary.BigEndian.Uint16(v)) != len(entries) {
				return result, fmt.Errorf("invalid key_share vector")
			}
			for len(entries) > 0 {
				if len(entries) < 4 {
					return result, fmt.Errorf("short key_share entry")
				}
				size := int(binary.BigEndian.Uint16(entries[2:4]))
				if size > len(entries)-4 {
					return result, fmt.Errorf("short key_share material")
				}
				extension.KeyShareGroups = append(extension.KeyShareGroups, binary.BigEndian.Uint16(entries))
				entries = entries[4+size:]
			}
		}
		result.Extensions = append(result.Extensions, extension)
	}
	return result, nil
}

type captureConn struct {
	net.Conn
	capture func(ClientHello)
	pending []byte
	done    bool
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.done && n > 0 {
		if len(c.pending)+n > 128<<10 {
			c.done = true
			c.pending = nil
		} else {
			c.pending = append(c.pending, p[:n]...)
			if hello, e := clientHello(c.pending); e == nil {
				c.done = true
				c.pending = nil
				c.capture(hello)
			}
		}
	}
	return n, err
}

type observedConn struct {
	net.Conn
	id         string
	store      *eventStore
	tlsConn    *tls.Conn
	pending    []byte
	captured   bool
	negotiated sync.Once
}

func (c *observedConn) Close() error {
	err := c.Conn.Close()
	c.store.mu.Lock()
	delete(c.store.active, c.id)
	c.store.mu.Unlock()
	return err
}

func (c *observedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.tlsConn != nil {
		state := c.tlsConn.ConnectionState()
		if state.HandshakeComplete {
			c.negotiated.Do(func() {
				c.store.emit(c.id, "tls.negotiated", map[string]any{"version": state.Version, "cipher_suite": state.CipherSuite, "alpn": state.NegotiatedProtocol, "resumed": state.DidResume})
			})
		}
	}
	if !c.captured && n > 0 {
		if len(c.pending)+n > 64<<10 {
			c.captured = true
			c.pending = nil
			c.store.emit(c.id, "http.capture_incomplete", map[string]string{"reason": "first header exceeds 64 KiB capture limit"})
		} else {
			c.pending = append(c.pending, p[:n]...)
			if end := bytes.Index(c.pending, []byte("\r\n\r\n")); end >= 0 {
				lines := strings.Split(string(c.pending[:end]), "\r\n")
				obs := httpObservation{RequestLine: lines[0], Scope: "first-request-per-connection"}
				for _, line := range lines[1:] {
					name, value, ok := strings.Cut(line, ":")
					if ok {
						if strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") {
							value = " [redacted]"
						}
						obs.Headers = append(obs.Headers, field{Name: name, Value: strings.TrimLeft(value, " \t")})
					}
				}
				c.captured = true
				c.pending = nil
				c.store.emit(c.id, "http1.headers", obs)
			}
		}
	}
	return n, err
}

type observationListener struct {
	net.Listener
	store     *eventStore
	tlsConfig *tls.Config
}

func (l observationListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	id := l.store.nextID()
	result := &observedConn{id: id, store: l.store}
	if l.tlsConfig != nil {
		raw := &captureConn{Conn: c, capture: func(hello ClientHello) { l.store.emit(id, "tls.client_hello", hello) }}
		tc := tls.Server(raw, l.tlsConfig)
		result.tlsConn = tc
		result.Conn = tc
	} else {
		result.Conn = c
	}
	l.store.mu.Lock()
	if l.store.closed {
		l.store.mu.Unlock()
		c.Close()
		return nil, net.ErrClosed
	}
	l.store.active[id] = result
	l.store.mu.Unlock()
	return result, nil
}
