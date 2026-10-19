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
func DecodeItems(data []byte) ([]Item, error) {
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
