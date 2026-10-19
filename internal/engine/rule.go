package engine

import (
	"fmt"
	"regexp"
)

// MatchKind names a generic byte-reading primitive. A rule selects exactly one
// of them.
//
// This is the seam that keeps rules and code decoupled: the Go side only knows
// how to *read bytes* (where an HTTP header's value is, where a MySQL handshake
// version string sits, where a TLS ServerHello starts). It has no idea what
// "nginx" or "SSH" is - that knowledge lives entirely in rules/*.yaml.
type MatchKind string

const (
	// MatchRegex applies the pattern to the raw banner.
	MatchRegex MatchKind = "regex"
	// MatchHTTPHeader extracts one HTTP response header value and applies the
	// pattern to that value instead of the whole banner.
	MatchHTTPHeader MatchKind = "http_header"
	// MatchMySQLHandshake extracts the server version out of a MySQL initial
	// handshake packet (binary wire format, not text).
	MatchMySQLHandshake MatchKind = "mysql_handshake"
	// MatchTLSRecord extracts the legacy version of a TLS ServerHello. A bare
	// session fragment does not qualify: see tlsServerHello for the evidence
	// threshold.
	MatchTLSRecord MatchKind = "tls_record"
)

// Match is the declarative matching instruction of a rule.
//
// Named capture groups carry the extracted values:
//
//	(?P<product>...)  optional, overrides Rule.Product
//	(?P<version>...)  optional, the version string reported back to the caller
type Match struct {
	Kind    MatchKind `yaml:"kind"`
	Pattern string    `yaml:"pattern"`
	// Header selects the field for kind=http_header (default: Server).
	Header string `yaml:"header,omitempty"`

	re         *regexp.Regexp
	versionIdx int
	productIdx int
}

// OSPattern maps an explicit operating-system token to a normalised os_hint.
//
// Only tokens that literally appear in the banner are reported; the engine never
// guesses an OS from a port number or a version number.
type OSPattern struct {
	Pattern string `yaml:"pattern"`
	Value   string `yaml:"value"`

	re *regexp.Regexp
}

// Rule is one fingerprint. Rules are data, loaded from rules/*.yaml (embedded at
// build time and optionally overridden by a mounted directory at run time).
type Rule struct {
	ID       string `yaml:"id"`
	Protocol string `yaml:"protocol"`
	// Product is the canonical product name used when the pattern does not
	// capture one itself.
	Product string `yaml:"product,omitempty"`
	// Confidence is the score of a *complete* match (product and version both
	// known). Missing components are subtracted in confidence().
	Confidence float64 `yaml:"confidence"`
	// Priority orders evaluation: higher runs first, first match wins. This is
	// how a specific rule always beats a generic fallback.
	Priority int `yaml:"priority,omitempty"`

	Match      Match       `yaml:"match"`
	OSPatterns []OSPattern `yaml:"os_patterns,omitempty"`
	Note       string      `yaml:"note,omitempty"`

	// source is the file the rule came from, used for error messages only.
	source string
}

func (r *Rule) compile() error {
	where := r.ID
	if where == "" {
		where = "<unnamed rule>"
	}
	if r.source != "" {
		where = r.source + ":" + where
	}
	if r.ID == "" {
		return fmt.Errorf("%s: id is required", where)
	}
	if r.Protocol == "" {
		return fmt.Errorf("%s: protocol is required", where)
	}
	if r.Confidence <= 0 || r.Confidence > 1 {
		return fmt.Errorf("%s: confidence must be in (0,1], got %v", where, r.Confidence)
	}
	if r.Match.Kind == "" {
		r.Match.Kind = MatchRegex
	}
	switch r.Match.Kind {
	case MatchRegex, MatchHTTPHeader, MatchMySQLHandshake, MatchTLSRecord:
	default:
		return fmt.Errorf("%s: unknown match kind %q", where, r.Match.Kind)
	}
	if r.Match.Pattern == "" {
		return fmt.Errorf("%s: match.pattern is required", where)
	}
	re, err := regexp.Compile(r.Match.Pattern)
	if err != nil {
		return fmt.Errorf("%s: invalid pattern: %w", where, err)
	}
	r.Match.re = re
	for i, name := range re.SubexpNames() {
		switch name {
		case "version":
			r.Match.versionIdx = i
		case "product":
			r.Match.productIdx = i
		}
	}
	if r.Match.Kind == MatchHTTPHeader && r.Match.Header == "" {
		r.Match.Header = "Server"
	}
	for i := range r.OSPatterns {
		p := &r.OSPatterns[i]
		if p.Pattern == "" || p.Value == "" {
			return fmt.Errorf("%s: every os_patterns entry needs pattern and value", where)
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return fmt.Errorf("%s: invalid os pattern: %w", where, err)
		}
		p.re = re
	}
	return nil
}

// evidence runs the rule's primitive and returns the text the pattern must be
// applied to. ok=false means the primitive found nothing it can interpret, so
// the rule simply does not apply.
func (r *Rule) evidence(banner string) (string, bool) {
	switch r.Match.Kind {
	case MatchHTTPHeader:
		v := httpHeaderValue(banner, r.Match.Header)
		return v, v != ""
	case MatchMySQLHandshake:
		v := mysqlServerVersion(banner)
		return v, v != ""
	case MatchTLSRecord:
		v := tlsServerHello(banner)
		return v, v != ""
	default:
		return banner, true
	}
}

// osHint reports the first declared OS token that literally appears in the
// banner (or in the extracted field, for header-based rules).
func (r *Rule) osHint(banner, field string) string {
	for _, p := range r.OSPatterns {
		if p.re.MatchString(field) {
			return p.Value
		}
		if field != banner && p.re.MatchString(banner) {
			return p.Value
		}
	}
	return ""
}

// matched runs the rule against the banner and returns the result fields.
func (r *Rule) matched(banner string) (product, version, osHint string, ok bool) {
	field, ok := r.evidence(banner)
	if !ok {
		return "", "", "", false
	}
	m := r.Match.re.FindStringSubmatch(field)
	if m == nil {
		return "", "", "", false
	}
	product = r.Product
	if r.Match.productIdx > 0 && r.Match.productIdx < len(m) && m[r.Match.productIdx] != "" {
		product = m[r.Match.productIdx]
	}
	if r.Match.versionIdx > 0 && r.Match.versionIdx < len(m) {
		version = m[r.Match.versionIdx]
	}
	return product, version, r.osHint(banner, field), true
}
