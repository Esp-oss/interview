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
