// Package engine turns raw scanner banners into fingerprints.
//
// The engine itself contains no protocol knowledge. It runs a compiled rule set
// (rules/*.yaml) against a banner and reports the first rule that matches, in
// priority order. Adding a protocol means adding YAML - never Go code.
package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/esp-oss/banner-fingerprint/internal/model"
)

// Tuning knobs of the confidence model. They are exported as constants so the
// documentation and the tests can refer to one source of truth.
const (
	// MaxBannerBytes bounds how much of a banner is inspected. Real banners are
	// a few hundred bytes; the cap keeps a hostile 10 MB "banner" from turning
	// into work.
	MaxBannerBytes = 64 << 10

	// versionPenalty is subtracted when a rule matches but cannot pin a version
	// (e.g. "Pure-FTPd" without a number, Redis which has no version banner).
	versionPenalty = 0.20
	// productPenalty is subtracted when a rule matches but cannot name a product.
	productPenalty = 0.05

	minConfidence = 0.30
	maxConfidence = 0.99
)

// Engine is a compiled, immutable rule set. Identify is safe for concurrent use.
type Engine struct {
	rules  []*Rule
	source string
}

// New compiles and validates a rule set. Rules are sorted by descending
// priority, ties broken by id so evaluation is deterministic across runs and
// machines.
func New(rules []*Rule, source string) (*Engine, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("engine: empty rule set (%s)", source)
	}
	seen := make(map[string]struct{}, len(rules))
	compiled := make([]*Rule, 0, len(rules))
	for _, r := range rules {
		if err := r.compile(); err != nil {
			return nil, fmt.Errorf("engine: %w", err)
		}
		if _, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("engine: duplicate rule id %q (last seen in %s)", r.ID, r.source)
		}
		seen[r.ID] = struct{}{}
		compiled = append(compiled, r)
	}
	sort.SliceStable(compiled, func(i, j int) bool {
		if compiled[i].Priority != compiled[j].Priority {
			return compiled[i].Priority > compiled[j].Priority
		}
		return compiled[i].ID < compiled[j].ID
	})
	return &Engine{rules: compiled, source: source}, nil
}

// Rules reports how many fingerprint rules are loaded.
func (e *Engine) Rules() int { return len(e.rules) }

// Source reports where the rule set came from (embedded, a directory, ...).
func (e *Engine) Source() string { return e.source }

// RuleIDs lists the loaded rule ids in evaluation order (useful for /health
// diagnostics and for tests that assert rule precedence).
func (e *Engine) RuleIDs() []string {
	ids := make([]string, len(e.rules))
	for i, r := range e.rules {
		ids[i] = r.ID
	}
	return ids
}

// Identify classifies one observation.
//
// It never fails: an unrecognised, empty, truncated or binary banner yields
// protocol "unknown" with confidence 0. The recover() is belt-and-braces - the
// fuzz test proves it is never needed - because one malformed record must never
// be able to abort a whole batch.
func (e *Engine) Identify(it model.Item) (res model.Result) {
	res = model.Unknown(it)
	defer func() {
		if recover() != nil {
			res = model.Unknown(it)
		}
	}()

	banner := it.Banner
	if len(banner) > MaxBannerBytes {
		banner = banner[:MaxBannerBytes]
	}
	if banner == "" {
		return res
	}

	for _, r := range e.rules {
		product, version, osHint, ok := r.matched(banner)
		if !ok {
			continue
		}
		return model.Result{
			IP:         it.IP,
			Port:       it.Port,
			Protocol:   r.Protocol,
			Product:    product,
			Version:    version,
			OSHint:     osHint,
			Confidence: confidence(r, product, version),
		}
	}
	return res
}

// IdentifyBatch classifies items concurrently with a bounded worker pool.
// Results keep the input order.
func (e *Engine) IdentifyBatch(items []model.Item, workers int) []model.Result {
	results := make([]model.Result, len(items))
	if len(items) == 0 {
		return results
	}
	if workers > len(items) {
		workers = len(items)
	}
	if workers <= 1 {
		for i := range items {
			results[i] = e.Identify(items[i])
		}
		return results
	}
	type job struct {
		idx  int
		item model.Item
	}
	jobs := make(chan job)
	done := make(chan struct{})
	for w := 0; w < workers; w++ {
		go func() {
			for j := range jobs {
				results[j.idx] = e.Identify(j.item)
			}
			done <- struct{}{}
		}()
	}
	go func() {
		for i := range items {
			jobs <- job{idx: i, item: items[i]}
		}
		close(jobs)
	}()
	for w := 0; w < workers; w++ {
		<-done
	}
	return results
}

// confidence implements the documented scoring model:
//
//	confidence = rule.confidence
//	           - 0.20  when no version could be extracted
//	           - 0.05  when no product could be named
//	           clamped to [0.30, 0.99]
//
// The port number deliberately plays no part: services move ports, and a rule
// that only fires on port 22 is worthless on an estate that runs SSH on 2222.
func confidence(r *Rule, product, version string) float64 {
	c := r.Confidence
	if version == "" {
		c -= versionPenalty
	}
	if product == "" {
		c -= productPenalty
	}
	if c < minConfidence {
		c = minConfidence
	}
	if c > maxConfidence {
		c = maxConfidence
	}
	// Round to two decimals so the API output is stable and readable.
	return float64(int(c*100+0.5)) / 100
}

// Summarise counts identities by protocol; handy for the client's footer.
func Summarise(results []model.Result) map[string]int {
	counts := make(map[string]int, len(results))
	for _, r := range results {
		counts[r.Protocol]++
	}
	return counts
}

// FormatProtocolCounts renders a stable "HTTP=3 SSH=2" style summary.
func FormatProtocolCounts(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
	}
	return strings.Join(parts, " ")
}
