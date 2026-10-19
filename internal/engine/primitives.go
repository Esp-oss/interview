package engine

import (
	"bytes"
	"strings"
)

// This file contains the only byte-layout knowledge that lives in Go. Each
// function is a *generic reader*: it locates a value inside a well-known wire
// format and returns it as text. Which service that value belongs to is decided
// exclusively by rules/*.yaml.
//
// Keeping the readers here (instead of encoding the structures as regexes in
// YAML) is what allows binary protocols such as MySQL and TLS to be recognised
// precisely while the naming policy stays editable without recompiling.

// httpHeaderValue returns the value of one HTTP response header.
//
// It accepts CRLF and bare-LF terminators, is case-insensitive on the header
// name, and returns "" when the banner is not an HTTP response or the header is
// absent. Only the header block is searched, so a "Server:" string inside an
// HTML body can never produce a false positive.
func httpHeaderValue(banner, name string) string {
	if !strings.HasPrefix(banner, "HTTP/") {
		return ""
	}
	head := banner
	if i := strings.Index(head, "\r\n\r\n"); i >= 0 {
		head = head[:i]
	} else if i := strings.Index(head, "\n\n"); i >= 0 {
		head = head[:i]
	}
	for _, line := range strings.Split(head, "\n") {
		line = strings.TrimRight(line, "\r")
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:colon]), name) {
			return strings.TrimSpace(line[colon+1:])
		}
	}
	return ""
}

// mysqlServerVersion extracts the server version from a MySQL initial handshake
// packet.
//
// Wire layout of the first packet:
//
//	3 bytes  payload length (little endian)
//	1 byte   sequence id
//	1 byte   protocol version (0x0a for MySQL 3.21+)
//	n bytes  server version, NUL terminated
//
// Real banners are frequently truncated or off by a few bytes, so a structural
// parse is attempted first and a bounded scan for a version-looking token is used
// as a fallback. Anything that does not look like a version string returns "".
func mysqlServerVersion(banner string) string {
	b := []byte(banner)
	if len(b) < 6 {
		return ""
	}
	// Canonical layout.
	if len(b) >= 7 && b[4] == 0x0a {
		if v := nulTerminatedToken(b[5:]); v != "" {
			return v
		}
	}
	// Tolerant layout: some scanners strip the 4-byte packet header.
	for i := 0; i+1 < len(b); i++ {
		if b[i] != 0x0a && b[i] != 0x00 {
			continue
		}
		if v := nulTerminatedToken(b[i+1:]); v != "" {
			return v
		}
	}
	return ""
}

// nulTerminatedToken reads a NUL-terminated token and validates that it looks
// like a software version ("8.0.32", "5.5.5-10.6.12-MariaDB", "8.0.32-0ubuntu0").
func nulTerminatedToken(b []byte) string {
	end := len(b)
	if i := bytes.IndexByte(b, 0); i >= 0 {
		end = i
	}
	if end > 64 {
		end = 64
	}
	tok := string(b[:end])
	if i := strings.IndexAny(tok, " \t\r\n"); i >= 0 {
		tok = tok[:i]
	}
	if !looksLikeVersion(tok) {
		return ""
	}
	return tok
}

func looksLikeVersion(s string) bool {
	if len(s) < 3 || len(s) > 64 {
		return false
	}
	if s[0] < '0' || s[0] > '9' {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c == '.', c == '-', c == '_', c == '+':
		default:
			return false
		}
	}
	return true
}

// TLS record / handshake constants.
const (
	tlsRecordHandshake       = 0x16 // record content type: handshake
	tlsHandshakeServerHello  = 0x02
	tlsServerHelloMinPayload = 38 // legacy_version(2)+random(32)+session_id_len(1)+cipher(2)+compression(1)
)

// tlsServerHello returns a normalised TLS version label ("TLS1.2", "TLS1.3", ...)
// when - and only when - the banner contains a complete ServerHello.
//
// EVIDENCE THRESHOLD: a four-byte session fragment (0x16 0x03 0x01 ...) proves a
// host speaks TLS, but it does not identify the peer and it does not even prove
// we captured a server response. Reporting "TLS" from that fragment would be a
// guess, and a wrong guess is worse than "unknown": see README "design
// decisions". Therefore only a full ServerHello (handshake type 0x02) yields a
// match; everything else stays unknown.
func tlsServerHello(banner string) string {
	b := []byte(banner)
	// record header (5) + handshake header (4) + legacy_version (2) + random (32)
	if len(b) < 43 {
		return ""
	}
	if b[0] != tlsRecordHandshake || b[1] != 0x03 {
		return ""
	}
	recordLen := int(b[3])<<8 | int(b[4])
	if recordLen < tlsServerHelloMinPayload {
		return ""
	}
	if b[5] != tlsHandshakeServerHello {
		return ""
	}
	return tlsVersionLabel(b[9], b[10])
}

func tlsVersionLabel(major, minor byte) string {
	if major != 0x03 {
		return ""
	}
	switch minor {
	case 0x00:
		return "SSL3.0"
	case 0x01:
		return "TLS1.0"
	case 0x02:
		return "TLS1.1"
	case 0x03:
		return "TLS1.2"
	case 0x04:
		return "TLS1.3"
	}
	return ""
}
