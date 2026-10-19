package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// DecodeItems decodes the batch payload accepted by POST /fingerprint and by the
// client's input file.
//
// Scanners are messy, so the decoder is deliberately lenient about the *shape*
// and strict about the *syntax*:
//
//	[{"ip":"1.2.3.4","port":22,"banner":"..."}, ...]   // canonical array
//	{"items": [ ... ]}                                 // envelope
//	{"ip": "1.2.3.4", "port": 22, "banner": "..."}      // single object
//
// Only syntactically broken JSON is an error. Every semantic oddity (missing
// banner, null banner, string port, extra fields, host:port in "ip") is
// normalised instead of rejected, because a scanner's bad record must degrade to
// "unknown" - never to an HTTP 4xx that kills the whole batch.
//
// One malformed-but-recoverable form is repaired instead of rejected: Python-style
// hex escapes ("\x00", "\x16") that scanners and test fixtures frequently emit.
// They are not valid JSON - only "\u0000" is - so a strict parse would reject the
// WHOLE batch, which is the one failure mode that can produce zero results. The
// strict parse is always attempted first; the repair only runs after it fails, so
// valid JSON is never reinterpreted.
func DecodeItems(data []byte) ([]Item, error) {
	items, err := decodeItems(data)
	if err == nil {
		return items, nil
	}
	normalized, changed := normalizeHexEscapes(data)
	if !changed {
		return nil, err
	}
	items, repaired := decodeItems(normalized)
	if repaired != nil {
		// Still broken for a reason the repair cannot fix: report the original
		// syntax error instead of a confusing "after repair" one.
		return nil, err
	}
	for i := range items {
		items[i].Banner = foldLatin1(items[i].Banner)
	}
	return items, nil
}

// decodeItems is the strict decoder used by DecodeItems (and retried after the
// hex-escape repair).
func decodeItems(data []byte) ([]Item, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("empty body")
	}
	switch trimmed[0] {
	case '[':
		var items []Item
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, fmt.Errorf("batch array: %w", err)
		}
		if items == nil {
			items = []Item{}
		}
		return items, nil
	case '{':
		var envelope struct {
			Items []Item `json:"items"`
		}
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &probe); err != nil {
			return nil, fmt.Errorf("object: %w", err)
		}
		if raw, ok := probe["items"]; ok {
			if err := json.Unmarshal(raw, &envelope.Items); err != nil {
				return nil, fmt.Errorf("envelope.items: %w", err)
			}
			if envelope.Items == nil {
				envelope.Items = []Item{}
			}
			return envelope.Items, nil
		}
		var one Item
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return nil, fmt.Errorf("single item: %w", err)
		}
		return []Item{one}, nil
	default:
		return nil, errors.New("body must be a JSON object or array")
	}
}

// UnmarshalJSON implements the tolerant field mapping described on DecodeItems.
// A record is never rejected: unknown or mistyped fields are dropped.
func (it *Item) UnmarshalJSON(data []byte) error {
	var raw struct {
		IP       json.RawMessage `json:"ip"`
		Host     json.RawMessage `json:"host"`
		Addr     json.RawMessage `json:"addr"`
		Port     json.RawMessage `json:"port"`
		Banner   json.RawMessage `json:"banner"`
		Response json.RawMessage `json:"response"`
		Payload  json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	it.IP = firstString(raw.IP, raw.Host, raw.Addr)
	it.Port = firstInt(raw.Port)
	// "addr" is sometimes "host:port"; recover the port when no explicit one.
	if it.Port == 0 && len(raw.Addr) > 0 {
		if host, port, err := net.SplitHostPort(firstString(raw.Addr)); err == nil {
			it.IP = host
			it.Port, _ = strconv.Atoi(port)
		}
	}
	it.Banner = firstString(raw.Banner, raw.Response, raw.Payload)
	return nil
}

func firstString(candidates ...json.RawMessage) string {
	for _, c := range candidates {
		if len(c) == 0 {
			continue
		}
		var s string
		if err := json.Unmarshal(c, &s); err == nil {
			return s
		}
		// Numbers are accepted as text: some scanners emit ports/banners as
		// bare numeric tokens.
		var n json.Number
		if err := json.Unmarshal(c, &n); err == nil {
			return n.String()
		}
	}
	return ""
}

func firstInt(candidates ...json.RawMessage) int {
	for _, c := range candidates {
		if len(c) == 0 {
			continue
		}
		var i int
		if err := json.Unmarshal(c, &i); err == nil {
			return i
		}
		var f float64
		if err := json.Unmarshal(c, &f); err == nil {
			return int(f)
		}
		var s string
		if err := json.Unmarshal(c, &s); err == nil {
			if i, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
				return i
			}
		}
	}
	return 0
}

// EncodeResults writes the batch answer. It keeps the input order so callers can
// zip input and output without extra keys.
func EncodeResults(results []Result) ([]byte, error) {
	if results == nil {
		results = []Result{}
	}
	return json.Marshal(results)
}

// normalizeHexEscapes rewrites Python-style "\xHH" escapes into the JSON-legal
// "\u00HH" form, and reports whether anything changed.
//
// It is escape-aware on purpose: it only looks inside JSON string literals, and it
// copies every other escape sequence verbatim. That means a banner containing the
// literal text "\x41" (written "\\x41" in JSON) is left untouched - only a real
// "\xHH" byte escape is repaired.
func normalizeHexEscapes(data []byte) ([]byte, bool) {
	out := make([]byte, 0, len(data)+16)
	changed := false
	inString := false

	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			out = append(out, c)
			continue
		}
		switch c {
		case '\\':
			if i+1 >= len(data) {
				out = append(out, c)
				continue
			}
			next := data[i+1]
			if (next == 'x' || next == 'X') && i+3 < len(data) &&
				isHexDigit(data[i+2]) && isHexDigit(data[i+3]) {
				out = append(out, '\\', 'u', '0', '0', data[i+2], data[i+3])
				i += 3
				changed = true
				continue
			}
			// Any other escape (including "\\") is copied as a pair so the
			// following character is never re-examined out of context.
			out = append(out, c, next)
			i++
		case '"':
			inString = false
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	if !changed {
		return nil, false
	}
	return out, true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// foldLatin1 maps U+0080..U+00FF back to single bytes.
//
// It is only applied on the repaired path, where the caller used Python-style byte
// escapes: "\xa5" means the byte 0xA5, but JSON's "\u00a5" decodes to the code
// point U+00A5, which Go stores as the two UTF-8 bytes 0xC2 0xA5. Folding restores
// byte fidelity so binary banners stay at their real length. Text above U+00FF
// (genuine UTF-8) is untouched.
func foldLatin1(s string) string {
	needs := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 0xC2 && s[i] <= 0xC3 {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 0x80 && r <= 0xFF {
			b.WriteByte(byte(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
