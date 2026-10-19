package model_test

import (
	"encoding/json"
	"testing"

	"github.com/esp-oss/banner-fingerprint/internal/model"
)

func TestDecodeItemsShapes(t *testing.T) {
	cases := []struct {
		name  string
		input string
		count int
	}{
		{"array", `[{"ip":"1.1.1.1","port":1,"banner":"x"},{"ip":"2.2.2.2","port":2,"banner":"y"}]`, 2},
		{"envelope", `{"items":[{"ip":"1.1.1.1","port":1,"banner":"x"}]}`, 1},
		{"single object", `{"ip":"1.1.1.1","port":1,"banner":"x"}`, 1},
		{"empty array", `[]`, 0},
		{"empty envelope", `{"items":[]}`, 0},
		{"null items", `{"items":null}`, 0},
		{"whitespace", "  \n\t[ ] \n", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			items, err := model.DecodeItems([]byte(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(items) != tc.count {
				t.Fatalf("got %d items, want %d", len(items), tc.count)
			}
		})
	}
}

func TestDecodeItemsLeniency(t *testing.T) {
	items, err := model.DecodeItems([]byte(`[
		{"ip":"1.1.1.1","port":"22","banner":"hi"},
		{"addr":"10.0.0.1:3306","banner":"j"},
		{"host":"3.3.3.3","port":80.0,"response":"r","payload":"ignored"},
		{"ip":null,"port":null,"banner":null},
		{"unknown":"field"}
	]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 5 {
		t.Fatalf("got %d items", len(items))
	}
	if items[0].Port != 22 || items[0].Banner != "hi" {
		t.Fatalf("string port: %+v", items[0])
	}
	if items[1].IP != "10.0.0.1" || items[1].Port != 3306 {
		t.Fatalf("addr split: %+v", items[1])
	}
	if items[2].IP != "3.3.3.3" || items[2].Port != 80 || items[2].Banner != "r" {
		t.Fatalf("aliases: %+v", items[2])
	}
	if items[3].IP != "" || items[3].Port != 0 || items[3].Banner != "" {
		t.Fatalf("nulls: %+v", items[3])
	}
}

func TestDecodeItemsErrors(t *testing.T) {
	for _, input := range []string{"", "   ", "not json", `[{"ip":}]`, `{"a":}`, `123`, `"str"`} {
		if _, err := model.DecodeItems([]byte(input)); err == nil {
			t.Fatalf("expected an error for %q", input)
		}
	}
}

func TestUnknownShape(t *testing.T) {
	got := model.Unknown(model.Item{IP: "1.2.3.4", Port: 22, Banner: "whatever"})
	if got.Protocol != model.UnknownProtocol {
		t.Fatalf("protocol = %q", got.Protocol)
	}
	if got.Confidence != 0 || got.Product != "" || got.Version != "" || got.OSHint != "" {
		t.Fatalf("unknown must be empty: %+v", got)
	}
	if got.IP != "1.2.3.4" || got.Port != 22 {
		t.Fatalf("endpoint must be kept: %+v", got)
	}
}

// The JSON field set is the API contract: exactly seven keys, stable names.
func TestResultJSONContract(t *testing.T) {
	raw, err := json.Marshal(model.Result{IP: "1.1.1.1", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "9.3", OSHint: "Debian", Confidence: 0.95})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"ip":"1.1.1.1","port":22,"protocol":"SSH","product":"OpenSSH","version":"9.3","os_hint":"Debian","confidence":0.95}`
	if string(raw) != want {
		t.Fatalf("contract drift:\n got %s\nwant %s", raw, want)
	}
}

// Scanner dumps and the task statement itself use Python-style "\x00" escapes,
// which are not valid JSON. Rejecting them would fail the whole batch - the one
// failure mode that produces zero results - so they are repaired.
func TestDecodeItemsRepairsPythonHexEscapes(t *testing.T) {
	raw := `[{"ip":"1.2.3.7","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}]`
	items, err := model.DecodeItems([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	want := "J\x00\x00\x00\n8.0.32\x00" // real NUL bytes and a real LF
	if items[0].Banner != want {
		t.Fatalf("banner = %q, want %q", items[0].Banner, want)
	}
}

// Bytes above 0x7F must stay single bytes: "\xa5" is the byte 0xA5, not the
// two-byte UTF-8 encoding of U+00A5.
func TestDecodeItemsHexEscapesKeepHighBytes(t *testing.T) {
	items, err := model.DecodeItems([]byte(`[{"banner":"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"}]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := []byte(items[0].Banner)
	if len(got) != 9 {
		t.Fatalf("banner length = %d, want 9 (% x)", len(got), got)
	}
	if got[4] != 0xa5 {
		t.Fatalf("byte 4 = 0x%02x, want 0xa5 (% x)", got[4], got)
	}
}

// The repair must not touch a literal backslash: only a real "\xHH" byte escape is
// rewritten. The second record makes the strict parse fail, which is what puts the
// whole document on the repair path.
func TestDecodeItemsLeavesEscapedBackslashAlone(t *testing.T) {
	items, err := model.DecodeItems([]byte(`[{"banner":"a\\x41b"},{"banner":"c\x00d"}]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if items[0].Banner != `a\x41b` {
		t.Fatalf("literal backslash was rewritten: %q", items[0].Banner)
	}
	if items[1].Banner != "c\x00d" {
		t.Fatalf("real escape was not repaired: %q", items[1].Banner)
	}
}

// The repair is a fallback, not a licence to accept anything.
func TestDecodeItemsStillRejectsRealSyntaxErrors(t *testing.T) {
	for _, input := range []string{`[{"ip":}]`, `{`, `not json`, `[{"banner":"\xZZ"}]`, `[{"banner":"\x0"}]`} {
		if _, err := model.DecodeItems([]byte(input)); err == nil {
			t.Fatalf("expected an error for %q", input)
		}
	}
}

// FuzzDecodeItemsNoPanic exercises the escape-aware repair state machine with
// arbitrary bytes. Besides panics (truncated escapes, unterminated strings,
// indices at the end of the buffer) it asserts a real invariant: anything the
// decoder accepts must survive a round trip through its own encoder.
func FuzzDecodeItemsNoPanic(f *testing.F) {
	seeds := []string{
		`[{"ip":"1.2.3.4","port":22,"banner":"x"}]`,
		`{"items":[]}`,
		`{"ip":"1.1.1.1","port":1,"banner":"y"}`,
		`[{"banner":"J\x00\x00\x00\n8.0.32\x00"}]`,
		`[{"banner":"a\\x41b"}]`,
		`[{"banner":"\x16\x03\x01\x00\xa5"}]`,
		`[{"banner":"\x"}]`,
		`[{"banner":"\xZZ"}]`,
		`[{"banner":"\x0"}]`,
		`[{"banner":"\u0000","port":"22","addr":"1.1.1.1:22"}]`,
		``,
		`[]`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		items, err := model.DecodeItems([]byte(input))
		if err != nil {
			return
		}
		encoded, marshalErr := json.Marshal(items)
		if marshalErr != nil {
			t.Fatalf("accepted input produced unencodable items: %v", marshalErr)
		}
		if _, decodeErr := model.DecodeItems(encoded); decodeErr != nil {
			t.Fatalf("own encoding does not decode: %v (encoded %s)", decodeErr, encoded)
		}
	})
}
