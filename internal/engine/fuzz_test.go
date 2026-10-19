package engine_test

import (
	"testing"

	"github.com/esp-oss/banner-fingerprint/internal/model"
)

// FuzzIdentifyNoPanic is the executable proof of the "must never crash" rule: it
// feeds arbitrary bytes, sizes and port numbers through the engine and asserts the
// invariants that the API contract depends on.
func FuzzIdentifyNoPanic(f *testing.F) {
	eng := newEngine(f)

	seeds := []struct {
		banner string
		port   int
	}{
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", 22},
		{"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0", 80},
		{"J\x00\x00\x00\n8.0.32\x00", 3306},
		{"-ERR unknown command", 6379},
		{"220 Welcome to Pure-FTPd", 21},
		{"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1", 9999},
		{"", 0},
		{"\x00\x00\x00\x00\x0a", 3306},
		{"HTTP/1.1 200 OK\r\nServer: Jetty/9.4.51", 8080},
		{"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n", 6379},
	}
	for _, s := range seeds {
		f.Add(s.banner, s.port)
	}

	f.Fuzz(func(t *testing.T, banner string, port int) {
		got := eng.Identify(model.Item{IP: "1.2.3.4", Port: port, Banner: banner})

		if got.Protocol == "" {
			t.Fatalf("protocol must never be empty (banner %q)", banner)
		}
		if got.Confidence < 0 || got.Confidence > 1 {
			t.Fatalf("confidence %v out of [0,1] (banner %q)", got.Confidence, banner)
		}
		if got.Protocol == model.UnknownProtocol {
			if got.Confidence != 0 || got.Product != "" || got.Version != "" {
				t.Fatalf("unknown results must be empty and zero-confidence: %+v", got)
			}
		}
		if got.IP != "1.2.3.4" || got.Port != port {
			t.Fatalf("endpoint must be echoed verbatim: %+v", got)
		}
	})
}
