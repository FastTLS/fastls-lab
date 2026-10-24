package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

func tokenContains(value, token string) bool {
	for _, v := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(v), token) {
			return true
		}
	}
	return false
}
func (l *Lab) websocket(w http.ResponseWriter, r *http.Request, c *observedConn) {
	key := r.Header.Get("Sec-WebSocket-Key")
	decoded, err := base64.StdEncoding.DecodeString(key)
	if r.Method != "GET" || r.ProtoMajor != 1 || r.ProtoMinor != 1 || !tokenContains(r.Header.Get("Connection"), "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.Header.Get("Sec-WebSocket-Version") != "13" || err != nil || len(decoded) != 16 {
		l.store.emit(c.id, "ws.handshake_rejected", map[string]string{"reason": "invalid HTTP1 WebSocket handshake"})
		http.Error(w, "invalid WebSocket handshake", 400)
		return
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unavailable", 500)
		return
	}
	connection, rw, err := h.Hijack()
	if err != nil {
		return
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(15 * time.Second))
	digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(digest[:])
	if _, err = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		return
	}
	if err = rw.Flush(); err != nil {
		return
	}
	l.store.emit(c.id, "ws.handshake_accepted", map[string]any{"transport": "http1-upgrade", "offered_subprotocols": r.Header.Get("Sec-WebSocket-Protocol"), "selected_subprotocol": "", "offered_extensions": r.Header.Get("Sec-WebSocket-Extensions"), "selected_extensions": ""})
	var message []byte
	var messageOpcode byte
	fail := func(code uint16, reason string) {
		l.store.emit(c.id, "ws.protocol_error", map[string]any{"code": code, "reason": reason})
		payload := binary.BigEndian.AppendUint16(nil, code)
		payload = append(payload, []byte(reason)...)
		_ = writeFrame(rw, 8, payload)
	}
	for frameIndex := 0; frameIndex < 256; frameIndex++ {
		f, err := readFrame(rw.Reader)
		if err != nil {
			if err != io.EOF {
				fail(1002, err.Error())
			}
			return
		}
		l.store.emit(c.id, "ws.frame", map[string]any{"opcode": f.opcode, "fin": f.fin, "masked": true, "payload_bytes": len(f.payload), "frame_index": frameIndex})
		switch f.opcode {
		case 8:
			if !validClose(f.payload) {
				fail(1002, "invalid close payload")
				return
			}
			_ = writeFrame(rw, 8, f.payload)
			l.store.emit(c.id, "ws.closed", map[string]any{"normal": true})
			return
		case 9:
			if err = writeFrame(rw, 10, f.payload); err != nil {
				return
			}
			continue
		case 10:
			continue
		case 1, 2:
			if messageOpcode != 0 {
				fail(1002, "new message during fragmentation")
				return
			}
			messageOpcode = f.opcode
			message = f.payload
		case 0:
			if messageOpcode == 0 {
				fail(1002, "unexpected continuation")
				return
			}
			message = append(message, f.payload...)
		}
		if len(message) > 1<<20 {
			fail(1009, "message exceeds limit")
			return
		}
		if f.fin {
			if messageOpcode == 1 && !utf8.Valid(message) {
				fail(1007, "invalid UTF-8")
				return
			}
			if err = writeFrame(rw, messageOpcode, message); err != nil {
				return
			}
			message = nil
			messageOpcode = 0
		}
	}
	fail(1008, "frame limit reached")
}

type frame struct {
	fin     bool
	opcode  byte
	payload []byte
}

func readFrame(r io.Reader) (frame, error) {
	var f frame
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		return f, err
	}
	f.fin = h[0]&128 != 0
	f.opcode = h[0] & 15
	if h[0]&0x70 != 0 || h[1]&128 == 0 {
		return f, fmt.Errorf("reserved bits or unmasked client frame")
	}
	if f.opcode != 0 && f.opcode != 1 && f.opcode != 2 && f.opcode != 8 && f.opcode != 9 && f.opcode != 10 {
		return f, fmt.Errorf("invalid opcode")
	}
	length := uint64(h[1] & 127)
	if length == 126 {
		b := make([]byte, 2)
		if _, err := io.ReadFull(r, b); err != nil {
			return f, err
		}
		length = uint64(binary.BigEndian.Uint16(b))
		if length < 126 {
			return f, fmt.Errorf("noncanonical frame length")
		}
	}
	if length == 127 {
		b := make([]byte, 8)
		if _, err := io.ReadFull(r, b); err != nil {
			return f, err
		}
		length = binary.BigEndian.Uint64(b)
		if length < 65536 {
			return f, fmt.Errorf("noncanonical frame length")
		}
	}
	if length > 1<<20 {
		return f, fmt.Errorf("frame exceeds limit")
	}
	if f.opcode >= 8 && (!f.fin || length > 125) {
		return f, fmt.Errorf("invalid control frame")
	}
	mask := make([]byte, 4)
	if _, err := io.ReadFull(r, mask); err != nil {
		return f, err
	}
	f.payload = make([]byte, int(length))
	if _, err := io.ReadFull(r, f.payload); err != nil {
		return f, err
	}
	for i := range f.payload {
		f.payload[i] ^= mask[i%4]
	}
	return f, nil
}
func writeFrame(w *bufio.ReadWriter, opcode byte, payload []byte) error {
	if err := w.WriteByte(0x80 | opcode); err != nil {
		return err
	}
	switch {
	case len(payload) < 126:
		if err := w.WriteByte(byte(len(payload))); err != nil {
			return err
		}
	case len(payload) <= 65535:
		if _, err := w.Write(binary.BigEndian.AppendUint16([]byte{126}, uint16(len(payload)))); err != nil {
			return err
		}
	default:
		if _, err := w.Write(binary.BigEndian.AppendUint64([]byte{127}, uint64(len(payload)))); err != nil {
			return err
		}
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return w.Flush()
}
func validClose(payload []byte) bool {
	if len(payload) == 0 {
		return true
	}
	if len(payload) < 2 || !utf8.Valid(payload[2:]) {
		return false
	}
	code := binary.BigEndian.Uint16(payload)
	if code >= 3000 && code <= 4999 {
		return true
	}
	return code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006
}
