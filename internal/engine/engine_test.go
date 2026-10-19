package engine_test

import (
	"strings"
	"testing"

	"github.com/esp-oss/banner-fingerprint/internal/engine"
	"github.com/esp-oss/banner-fingerprint/internal/model"
	"github.com/esp-oss/banner-fingerprint/rules"
)

func newEngine(t testing.TB) *engine.Engine {
	t.Helper()
	loaded, source, err := engine.Load(rules.Embedded)
	if err != nil {
		t.Fatalf("load embedded rules: %v", err)
	}
	eng, err := engine.New(loaded, source)
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return eng
}

type want struct {
	protocol string
	product  string
	version  string
	osHint   string
	conf     float64
}

// The twenty observations from the task statement, plus the expected answer for
// each. The first seven are the ones published in the assignment; the rest were
// derived from the same rules and are asserted so a future rule edit cannot
// silently break them.
func TestIdentifyCorpus(t *testing.T) {
	eng := newEngine(t)

	cases := []struct {
		name   string
		port   int
		banner string
		want   want
	}{
		{
			name: "openssh ubuntu", port: 22,
			banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
			want:   want{"SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95},
		},
		{
			name: "nginx", port: 80,
			banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html",
			want:   want{"HTTP", "nginx", "1.24.0", "", 0.90},
		},
		{
			name: "apache", port: 443,
			banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57",
			want:   want{"HTTP", "Apache", "2.4.57", "", 0.90},
		},
		{
			name: "mysql binary handshake", port: 3306,
			banner: "J\x00\x00\x00\n8.0.32\x00",
			want:   want{"MySQL", "MySQL", "8.0.32", "", 0.90},
		},
		{
			name: "redis error reply", port: 6379,
			banner: "-ERR wrong number of arguments for 'get' command",
			want:   want{"Redis", "Redis", "", "", 0.70},
		},
		{
			name: "proftpd", port: 21,
			banner: "220 ProFTPD 1.3.7 Server (ProFTPD)",
			want:   want{"FTP", "ProFTPD", "1.3.7", "", 0.90},
		},
		{
			name: "jetty on 8080", port: 8080,
			banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51",
			want:   want{"HTTP", "Jetty", "9.4.51", "", 0.85},
		},
		{
			name: "openssh debian", port: 22,
			banner: "SSH-2.0-OpenSSH_9.3 Debian-1",
			want:   want{"SSH", "OpenSSH", "9.3", "Debian", 0.95},
		},
		{
			name: "nginx ubuntu", port: 80,
			banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)",
			want:   want{"HTTP", "nginx", "1.18.0", "Ubuntu", 0.90},
		},
		{
			name: "apache ubuntu", port: 443,
			banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)",
			want:   want{"HTTP", "Apache", "2.4.41", "Ubuntu", 0.90},
		},
		{
			name: "mysql 5.7", port: 3306,
			banner: "J\x00\x00\x00\n5.7.42\x00",
			want:   want{"MySQL", "MySQL", "5.7.42", "", 0.90},
		},
		{
			name: "redis pong", port: 6379,
			banner: "+PONG",
			want:   want{"Redis", "Redis", "", "", 0.70},
		},
		{
			name: "vsftpd", port: 21,
			banner: "220 (vsFTPd 3.0.5)",
			want:   want{"FTP", "vsFTPd", "3.0.5", "", 0.90},
		},
		{
			name: "nginx on 8443", port: 8443,
			banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3",
			want:   want{"HTTP", "nginx", "1.25.3", "", 0.90},
		},
		{
			name: "ssh 1.99 legacy", port: 22,
			banner: "SSH-1.99-OpenSSH_4.3",
			want:   want{"SSH", "OpenSSH", "4.3", "", 0.95},
		},
		{
			name: "tls fragment stays unknown", port: 9999,
			banner: "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1",
			want:   want{"unknown", "", "", "", 0.00},
		},
		{
			name: "iis", port: 8888,
			banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0",
			want:   want{"HTTP", "Microsoft-IIS", "10.0", "Windows", 0.90},
		},
		{
			name: "redis noauth", port: 6379,
			banner: "-NOAUTH Authentication required.",
			want:   want{"Redis", "Redis", "", "", 0.70},
		},
		{
			name: "pure-ftpd without version", port: 21,
			banner: "220 Welcome to Pure-FTPd",
			want:   want{"FTP", "Pure-FTPd", "", "", 0.75},
		},
		{
			name: "random command stays unknown", port: 12345,
			banner: "QUIT\r\n",
			want:   want{"unknown", "", "", "", 0.00},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := eng.Identify(model.Item{IP: "1.2.3.4", Port: tc.port, Banner: tc.banner})
			if got.Protocol != tc.want.protocol {
				t.Fatalf("protocol = %q, want %q (banner %q)", got.Protocol, tc.want.protocol, tc.banner)
			}
			if got.Product != tc.want.product {
				t.Fatalf("product = %q, want %q", got.Product, tc.want.product)
			}
			if got.Version != tc.want.version {
				t.Fatalf("version = %q, want %q", got.Version, tc.want.version)
			}
			if got.OSHint != tc.want.osHint {
				t.Fatalf("os_hint = %q, want %q", got.OSHint, tc.want.osHint)
			}
			if !closeEnough(got.Confidence, tc.want.conf) {
				t.Fatalf("confidence = %v, want %v", got.Confidence, tc.want.conf)
			}
			if got.IP != "1.2.3.4" || got.Port != tc.port {
				t.Fatalf("endpoint not echoed: %+v", got)
			}
		})
	}
}

// A malformed or hostile record must degrade, never panic or leak a 500.
func TestIdentifyDegradesGracefully(t *testing.T) {
	eng := newEngine(t)
	banners := []string{
		"",
		" ",
		"\x00",
		"HTTP/1.1",
		"HTTP/1.1 200 OK", // no Server header -> generic HTTP
		"SSH-",
		"SSH-2.0-",
		"220",
		"-ERR",
		strings.Repeat("A", 100_000),
		"\xff\xfe\x00\x01binary\x00garbage\xff",
		"{\"not\":\"a banner\"}",
	}
	for _, banner := range banners {
		got := eng.Identify(model.Item{IP: "10.0.0.1", Port: 1, Banner: banner})
		if got.Protocol == "" {
			t.Fatalf("empty protocol for banner %q", banner)
		}
		if got.Confidence < 0 || got.Confidence > 1 {
			t.Fatalf("confidence out of range: %v", got.Confidence)
		}
		if got.Protocol == model.UnknownProtocol && got.Confidence != 0 {
			t.Fatalf("unknown result must have confidence 0, got %v", got.Confidence)
		}
	}
}

func TestHTTPWithoutServerHeader(t *testing.T) {
	eng := newEngine(t)
	got := eng.Identify(model.Item{IP: "1.1.1.1", Port: 80, Banner: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"})
	if got.Protocol != "HTTP" {
		t.Fatalf("protocol = %q, want HTTP", got.Protocol)
	}
	if got.Product != "" {
		t.Fatalf("product = %q, want empty", got.Product)
	}
	if got.Confidence >= 0.9 {
		t.Fatalf("protocol-only match must be less confident, got %v", got.Confidence)
	}
}

// SMTP and FTP both greet with 220; the mail rule must win, otherwise every mail
// server on the estate would be reported as FTP.
func TestSMTPBeatsFTPFallback(t *testing.T) {
	eng := newEngine(t)
	got := eng.Identify(model.Item{IP: "1.1.1.1", Port: 25, Banner: "220 mail.example.com ESMTP Postfix (Ubuntu)"})
	if got.Protocol != "SMTP" {
		t.Fatalf("protocol = %q, want SMTP", got.Protocol)
	}
	if got.Product != "Postfix" {
		t.Fatalf("product = %q, want Postfix", got.Product)
	}
	if got.OSHint != "Ubuntu" {
		t.Fatalf("os_hint = %q, want Ubuntu", got.OSHint)
	}
}

// Port must not influence the answer: the same banner on an unusual port has to
// produce the same fingerprint.
func TestPortDoesNotGateIdentification(t *testing.T) {
	eng := newEngine(t)
	banner := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
	on22 := eng.Identify(model.Item{IP: "1.1.1.1", Port: 22, Banner: banner})
	on2222 := eng.Identify(model.Item{IP: "1.1.1.1", Port: 2222, Banner: banner})
	if on22.Protocol != on2222.Protocol || on22.Confidence != on2222.Confidence {
		t.Fatalf("port changed the verdict: %+v vs %+v", on22, on2222)
	}
}

func TestRuleSetIsNonTrivial(t *testing.T) {
	eng := newEngine(t)
	if eng.Rules() < 10 {
		t.Fatalf("expected the shipped corpus to be substantial, got %d rules", eng.Rules())
	}
	for _, protocol := range []string{"SSH", "HTTP", "MySQL", "Redis", "FTP"} {
		found := false
		for _, id := range eng.RuleIDs() {
			if strings.Contains(strings.ToLower(id), strings.ToLower(protocol)) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("no rule id references %s (ids: %v)", protocol, eng.RuleIDs())
		}
	}
}

// The engine must refuse a broken rule set at load time instead of starting and
// mis-identifying everything.
func TestNewRejectsBadRules(t *testing.T) {
	bad := []*engine.Rule{
		{ID: "", Protocol: "SSH", Confidence: 0.9, Match: engine.Match{Kind: engine.MatchRegex, Pattern: "^x"}},
		{ID: "no-protocol", Confidence: 0.9, Match: engine.Match{Kind: engine.MatchRegex, Pattern: "^x"}},
		{ID: "bad-regex", Protocol: "SSH", Confidence: 0.9, Match: engine.Match{Kind: engine.MatchRegex, Pattern: "("}},
		{ID: "bad-kind", Protocol: "SSH", Confidence: 0.9, Match: engine.Match{Kind: "guess", Pattern: "^x"}},
		{ID: "bad-conf", Protocol: "SSH", Confidence: 42, Match: engine.Match{Kind: engine.MatchRegex, Pattern: "^x"}},
	}
	for _, r := range bad {
		if _, err := engine.New([]*engine.Rule{r}, "test"); err == nil {
			t.Fatalf("expected an error for rule %+v", r)
		}
	}
	if _, err := engine.New(nil, "test"); err == nil {
		t.Fatal("empty rule set must be rejected")
	}
}

func closeEnough(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 0.001
}

// A scanner that keeps only part of a response must still be identified: the
// header block is recognised without a status line.
func TestHTTPHeaderWithoutStatusLine(t *testing.T) {
	eng := newEngine(t)

	positive := []struct {
		name    string
		banner  string
		product string
		version string
		osHint  string
	}{
		{
			name:    "status line trimmed",
			banner:  "Server: nginx/1.24.0\r\nDate: Tue, 01 Jan 2024 00:00:00 GMT\r\nContent-Type: text/html",
			product: "nginx", version: "1.24.0",
		},
		{
			name:    "header only, bare LF, lowercase name",
			banner:  "server: Apache/2.4.41 (Ubuntu)\nX-Powered-By: PHP/8.2",
			product: "Apache", version: "2.4.41", osHint: "Ubuntu",
		},
		{
			name:    "header only, jetty",
			banner:  "Server: Jetty/9.4.51",
			product: "Jetty", version: "9.4.51",
		},
	}
	for _, tc := range positive {
		t.Run(tc.name, func(t *testing.T) {
			got := eng.Identify(model.Item{IP: "1.0.0.1", Port: 80, Banner: tc.banner})
			if got.Protocol != "HTTP" {
				t.Fatalf("protocol = %q, want HTTP (banner %q)", got.Protocol, tc.banner)
			}
			if got.Product != tc.product || got.Version != tc.version || got.OSHint != tc.osHint {
				t.Fatalf("got %+v, want product=%q version=%q os_hint=%q", got, tc.product, tc.version, tc.osHint)
			}
		})
	}
}

// The relaxed parser must not turn free text into HTTP: a mid-header block only
// counts when every leading line really is "Name: value".
func TestHTTPHeaderRejectsFreeText(t *testing.T) {
	eng := newEngine(t)
	for _, banner := range []string{
		"hello world\r\nServer: nginx/1.24.0",
		"220 mail.example.com ESMTP\r\nServer: nginx/1.24.0",
		"<html><body>Server: nginx/1.24.0</body></html>",
	} {
		got := eng.Identify(model.Item{IP: "1.0.0.2", Port: 80, Banner: banner})
		if got.Product == "nginx" {
			t.Fatalf("free text was mistaken for HTTP/nginx: %+v (banner %q)", got, banner)
		}
	}
}

// A header-looking line inside a response body must never be used as evidence.
func TestHTTPBodyIsNotSearchedForHeaders(t *testing.T) {
	eng := newEngine(t)
	banner := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>\r\nServer: nginx/9.9.9\r\n</html>"
	got := eng.Identify(model.Item{IP: "1.0.0.3", Port: 80, Banner: banner})
	if got.Version == "9.9.9" || got.Product == "nginx" {
		t.Fatalf("body line leaked into the fingerprint: %+v", got)
	}
	if got.Protocol != "HTTP" {
		t.Fatalf("protocol = %q, want HTTP", got.Protocol)
	}
}
