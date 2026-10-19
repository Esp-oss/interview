package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/esp-oss/banner-fingerprint/internal/api"
	"github.com/esp-oss/banner-fingerprint/internal/engine"
	"github.com/esp-oss/banner-fingerprint/internal/model"
	"github.com/esp-oss/banner-fingerprint/rules"
)

func newServer(t *testing.T, cfg api.Config) http.Handler {
	t.Helper()
	loaded, source, err := engine.Load(rules.Embedded)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	eng, err := engine.New(loaded, source)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	cfg.Version = "test"
	cfg.RulesSource = source
	return api.New(eng, cfg)
}

func post(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) []model.Result {
	t.Helper()
	var out []model.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestHealth(t *testing.T) {
	h := newServer(t, api.Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Status string `json:"status"`
		Rules  int    `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "ok" || body.Rules == 0 {
		t.Fatalf("unexpected health body: %+v", body)
	}
}

func TestHealthMethodNotAllowed(t *testing.T) {
	h := newServer(t, api.Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/health", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestFingerprintBatch(t *testing.T) {
	h := newServer(t, api.Config{})
	body := `[
	  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
	  {"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
	  {"ip":"1.2.3.6","port":9999,"banner":"garbage \u0000\u0001"}
	]`
	rec := post(t, h, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q", ct)
	}
	results := decode(t, rec)
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if results[0].Protocol != "SSH" || results[0].Product != "OpenSSH" || results[0].Version != "8.9p1" || results[0].OSHint != "Ubuntu" {
		t.Fatalf("ssh result wrong: %+v", results[0])
	}
	if results[1].Product != "nginx" || results[1].Version != "1.24.0" {
		t.Fatalf("nginx result wrong: %+v", results[1])
	}
	if results[2].Protocol != model.UnknownProtocol {
		t.Fatalf("garbage should be unknown, got %+v", results[2])
	}
	// Order must follow the request.
	if results[0].IP != "1.2.3.4" || results[2].IP != "1.2.3.6" {
		t.Fatalf("order not preserved: %+v", results)
	}
}

func TestFingerprintAcceptsEnvelopeAndSingleObject(t *testing.T) {
	h := newServer(t, api.Config{})

	envelope := post(t, h, `{"items":[{"ip":"1.1.1.1","port":6379,"banner":"+PONG"}]}`)
	if envelope.Code != http.StatusOK {
		t.Fatalf("envelope status = %d", envelope.Code)
	}
	if got := decode(t, envelope); len(got) != 1 || got[0].Protocol != "Redis" {
		t.Fatalf("envelope decode wrong: %+v", got)
	}

	single := post(t, h, `{"ip":"1.1.1.2","port":21,"banner":"220 ProFTPD 1.3.7 Server (ProFTPD)"}`)
	if single.Code != http.StatusOK {
		t.Fatalf("single status = %d", single.Code)
	}
	if got := decode(t, single); len(got) != 1 || got[0].Product != "ProFTPD" {
		t.Fatalf("single decode wrong: %+v", got)
	}
}

func TestFingerprintLenientFields(t *testing.T) {
	h := newServer(t, api.Config{})
	// port as string, addr with host:port, null banner, unknown extra field
	body := `[{"ip":"9.9.9.9","port":"22","banner":"SSH-2.0-OpenSSH_9.3","extra":true},
	          {"addr":"10.0.0.1:3306","banner":"J\u0000\u0000\u0000\n5.7.42\u0000"},
	          {"ip":"10.0.0.2","port":1234,"banner":null}]`
	rec := post(t, h, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	got := decode(t, rec)
	if len(got) != 3 {
		t.Fatalf("got %d results", len(got))
	}
	if got[0].Port != 22 {
		t.Fatalf("string port not coerced: %+v", got[0])
	}
	if got[1].IP != "10.0.0.1" || got[1].Port != 3306 || got[1].Product != "MySQL" {
		t.Fatalf("addr split failed: %+v", got[1])
	}
	if got[2].Protocol != model.UnknownProtocol {
		t.Fatalf("null banner should be unknown: %+v", got[2])
	}
}

func TestFingerprintEmptyBatch(t *testing.T) {
	h := newServer(t, api.Config{})
	rec := post(t, h, `[]`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty batch must serialise as [], got %q", rec.Body.String())
	}
}

func TestFingerprintRejectsBadJSON(t *testing.T) {
	h := newServer(t, api.Config{})
	for _, body := range []string{``, `not json`, `[{"ip":}]`, `{`, `123`} {
		rec := post(t, h, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q: status = %d, want 400", body, rec.Code)
		}
		var apiErr struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &apiErr); err != nil || apiErr.Error == "" {
			t.Fatalf("body %q: missing error payload: %s", body, rec.Body.String())
		}
	}
}

func TestFingerprintRejectsOversizedBody(t *testing.T) {
	h := newServer(t, api.Config{MaxBodyBytes: 128})
	big := `[{"ip":"1.1.1.1","port":1,"banner":"` + strings.Repeat("A", 512) + `"}]`
	rec := post(t, h, big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestFingerprintBatchLimit(t *testing.T) {
	h := newServer(t, api.Config{MaxBatch: 2})
	rec := post(t, h, `[{"ip":"1","port":1,"banner":""},{"ip":"2","port":1,"banner":""},{"ip":"3","port":1,"banner":""}]`)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestUnknownRoute(t *testing.T) {
	h := newServer(t, api.Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestFingerprintMethodNotAllowed(t *testing.T) {
	h := newServer(t, api.Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fingerprint", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// A garbage record must never make the endpoint answer 500, even when the whole
// batch is binary noise.
func TestFingerprintNeverFailsOnGarbage(t *testing.T) {
	h := newServer(t, api.Config{})
	var buf bytes.Buffer
	buf.WriteString(`[{"ip":"1.1.1.1","port":1,"banner":"\u0000\u0001\u0002"},`)
	buf.WriteString(`{"ip":"1.1.1.2","port":2,"banner":""},`)
	buf.WriteString(`{"ip":"1.1.1.3","port":3}]`)
	rec := post(t, h, buf.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	results := decode(t, rec)
	if len(results) != 3 {
		t.Fatalf("got %d results", len(results))
	}
	for _, r := range results {
		if r.Protocol == "" {
			t.Fatalf("empty protocol in %+v", r)
		}
	}
}

func TestRequestIDHeader(t *testing.T) {
	h := newServer(t, api.Config{})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Request-Id", "abc123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("X-Request-Id"); got != "abc123" {
		t.Fatalf("X-Request-Id = %q, want abc123", got)
	}
}
