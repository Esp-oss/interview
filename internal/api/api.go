// Package api exposes the HTTP surface of the fingerprint service.
//
// The package owns transport concerns only: body limits, decoding, status codes,
// logging, panics. It knows nothing about protocols, and it cannot name one.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"time"

	"github.com/esp-oss/banner-fingerprint/internal/engine"
	"github.com/esp-oss/banner-fingerprint/internal/model"
)

// Config carries the tunables of the HTTP layer. Zero values fall back to the
// defaults below, which keeps tests short.
type Config struct {
	MaxBatch     int
	MaxBodyBytes int64
	Workers      int
	Version      string
	RulesSource  string
	Logger       *slog.Logger
}

// Defaults used when Config leaves a field zero.
const (
	DefaultMaxBatch     = 5000
	DefaultMaxBodyBytes = 8 << 20 // 8 MiB
)

// New wires the routes and the middleware chain and returns a ready handler.
func New(eng *engine.Engine, cfg Config) http.Handler {
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = DefaultMaxBatch
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.GOMAXPROCS(0)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	h := &handler{
		eng:       eng,
		cfg:       cfg,
		log:       cfg.Logger,
		startedAt: time.Now(),
	}

	mux := http.NewServeMux()
	// Method-scoped patterns: Go's ServeMux answers 405 by itself when the path
	// matches but the method does not, which is exactly the contract we want.
	mux.HandleFunc("POST /fingerprint", h.fingerprint)
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("/", h.notFound)

	return recoverPanic(h.log, requestID(logRequests(h.log, mux)))
}

type handler struct {
	eng       *engine.Engine
	cfg       Config
	log       *slog.Logger
	startedAt time.Time
}

// health is both a liveness and a readiness probe: it only answers 200 when a
// rule set is loaded and the process can serve traffic. The container
// HEALTHCHECK calls this through the binary's own `healthcheck` subcommand (the
// runtime image is scratch, so there is no curl to call it with).
func (h *handler) health(w http.ResponseWriter, r *http.Request) {
	if h.eng == nil || h.eng.Rules() == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "reason": "no rules loaded"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"version":        h.cfg.Version,
		"rules":          h.eng.Rules(),
		"rules_source":   h.cfg.RulesSource,
		"workers":        h.cfg.Workers,
		"uptime_seconds": int64(time.Since(h.startedAt).Seconds()),
	})
}

// fingerprint classifies a batch and answers with a JSON array in input order.
//
// Failure policy, in one sentence: transport-level problems (unreadable body,
// oversized payload, too many items, syntactically broken JSON) are 4xx, while
// every per-record problem - unknown bytes, missing banner, binary garbage -
// degrades to protocol "unknown" inside the answer and never fails the request.
func (h *handler) fingerprint(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	r.Body = http.MaxBytesReader(w, r.Body, h.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("request body exceeds %d bytes", h.cfg.MaxBodyBytes))
			return
		}
		writeError(w, http.StatusBadRequest, "cannot read request body: "+err.Error())
		return
	}

	items, err := model.DecodeItems(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(items) > h.cfg.MaxBatch {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("batch of %d items exceeds MAX_BATCH=%d", len(items), h.cfg.MaxBatch))
		return
	}

	results := h.eng.IdentifyBatch(items, h.cfg.Workers)

	status := http.StatusOK
	writeResults(w, results)

	h.log.Info("fingerprint",
		"request_id", RequestID(r.Context()),
		"items", len(items),
		"status", status,
		"duration_ms", time.Since(started).Milliseconds(),
	)
}

func (h *handler) notFound(w http.ResponseWriter, r *http.Request) {
	// A known path with the wrong method must answer 405, not 404: the catch-all
	// "/" pattern would otherwise mask the method mismatch that http.ServeMux
	// reports for the method-scoped routes.
	switch r.URL.Path {
	case "/fingerprint", "/health":
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed,
			fmt.Sprintf("method %s not allowed on %s", r.Method, r.URL.Path))
	default:
		writeError(w, http.StatusNotFound, fmt.Sprintf("no route for %s %s", r.Method, r.URL.Path))
	}
}

// --- response helpers -------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeResults(w http.ResponseWriter, results []model.Result) {
	if results == nil {
		results = []model.Result{}
	}
	payload, err := json.Marshal(results)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot encode response")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

// --- middleware -------------------------------------------------------------

type ctxKey int

const requestIDKey ctxKey = iota

// RequestID returns the correlation id attached to the request context.
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// requestID assigns (or accepts) a correlation id so one line per request can be
// joined with client-side logs.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			var buf [8]byte
			if _, err := rand.Read(buf[:]); err == nil {
				id = hex.EncodeToString(buf[:])
			}
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

type recorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// logRequests emits one structured line per request (method, path, status,
// bytes, latency, correlation id).
func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		rec := &recorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		level := slog.LevelInfo
		if status >= 500 {
			level = slog.LevelError
		} else if status >= 400 {
			level = slog.LevelWarn
		}
		log.Log(r.Context(), level, "http",
			"request_id", RequestID(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"bytes", rec.bytes,
			"remote", r.RemoteAddr,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

// recoverPanic keeps one bad request from taking the process down.
func recoverPanic(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Error("panic recovered",
					"request_id", RequestID(r.Context()),
					"method", r.Method,
					"path", r.URL.Path,
					"panic", fmt.Sprint(rec),
				)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
