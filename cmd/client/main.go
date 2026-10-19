// Command client is the standalone consumer of the fingerprint server.
//
// It reads a local JSON file of scanner observations, posts them to the server,
// and renders the answer. It is a separate program and a separate container: the
// server never imports it, and it never imports the server.
//
// Examples:
//
//	client -file examples/sample_input.json
//	client -file data.json -server http://127.0.0.1:8080 -output json
//	client -file data.json -expected examples/expected_output.json   # self-test
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/esp-oss/banner-fingerprint/internal/model"
)

const (
	exitOK       = 0
	exitMismatch = 1
	exitUsage    = 2
	exitServer   = 3
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		file     = flag.String("file", envOr("INPUT_FILE", ""), "input JSON file ('-' reads stdin)")
		server   = flag.String("server", envOr("SERVER_URL", "http://127.0.0.1:8080"), "server base URL")
		output   = flag.String("output", "table", "output format: table|json")
		expected = flag.String("expected", "", "optional expected-results JSON file; exit 1 on mismatch")
		timeout  = flag.Duration("timeout", 30*time.Second, "per-request timeout")
		retries  = flag.Int("retries", 5, "retries while the server is still starting")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s -file <input.json> [flags]\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if strings.TrimSpace(*file) == "" {
		fmt.Fprintln(os.Stderr, "client: -file is required")
		flag.Usage()
		return exitUsage
	}

	items, err := readItems(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		return exitUsage
	}

	results, err := fingerprint(*server, items, *timeout, *retries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		return exitServer
	}

	switch strings.ToLower(*output) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(os.Stderr, "client: %v\n", err)
			return exitUsage
		}
	case "table", "":
		renderTable(os.Stdout, results)
		renderSummary(os.Stdout, results)
	default:
		fmt.Fprintf(os.Stderr, "client: unknown -output %q (want table|json)\n", *output)
		return exitUsage
	}

	if *expected != "" {
		want, err := readResults(*expected)
		if err != nil {
			fmt.Fprintf(os.Stderr, "client: %v\n", err)
			return exitUsage
		}
		if ok := compare(os.Stdout, want, results); !ok {
			return exitMismatch
		}
	}
	return exitOK
}

func readItems(path string) ([]model.Item, error) {
	data, err := readInput(path)
	if err != nil {
		return nil, err
	}
	items, err := model.DecodeItems(data)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return items, nil
}

func readResults(path string) ([]model.Result, error) {
	data, err := readInput(path)
	if err != nil {
		return nil, err
	}
	var results []model.Result
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return results, nil
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

// fingerprint posts the batch, retrying with exponential backoff so that
// `docker compose up` works even when the client container wins the race against
// the server's first healthy second.
func fingerprint(server string, items []model.Item, timeout time.Duration, retries int) ([]model.Result, error) {
	payload, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	url := strings.TrimRight(server, "/") + "/fingerprint"
	client := &http.Client{Timeout: timeout}

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode != http.StatusOK {
			var apiErr struct {
				Error string `json:"error"`
			}
			if json.Unmarshal(body, &apiErr) == nil && apiErr.Error != "" {
				return nil, fmt.Errorf("server %s: %s", resp.Status, apiErr.Error)
			}
			lastErr = fmt.Errorf("server returned %s", resp.Status)
			continue
		}
		var results []model.Result
		if err := json.Unmarshal(body, &results); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
		return results, nil
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", retries+1, lastErr)
}

func renderTable(w io.Writer, results []model.Result) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONF")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			dash(r.IP), r.Port, dash(r.Protocol), dash(r.Product), dash(r.Version), dash(r.OSHint), r.Confidence)
	}
	_ = tw.Flush()
}

func renderSummary(w io.Writer, results []model.Result) {
	counts := make(map[string]int, len(results))
	unknown := 0
	for _, r := range results {
		counts[r.Protocol]++
		if r.Protocol == model.UnknownProtocol {
			unknown++
		}
	}
	known := len(results) - unknown
	ratio := 0.0
	if len(results) > 0 {
		ratio = float64(known) / float64(len(results)) * 100
	}
	fmt.Fprintf(w, "\n%d items | %d identified | %d unknown (%.1f%% coverage)\n",
		len(results), known, unknown, ratio)

	order := []string{"SSH", "HTTP", "HTTPS", "TLS", "MySQL", "Redis", "FTP", "SMTP", "IMAP", "POP3", model.UnknownProtocol}
	seen := make(map[string]bool, len(order))
	var parts []string
	for _, proto := range order {
		if n, ok := counts[proto]; ok {
			parts = append(parts, fmt.Sprintf("%s=%d", proto, n))
			seen[proto] = true
		}
	}
	for proto, n := range counts {
		if !seen[proto] {
			parts = append(parts, fmt.Sprintf("%s=%d", proto, n))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, "by protocol: %s\n", strings.Join(parts, " "))
	}
}

// compare diffs the response against an expected file. It exists so the project
// can prove its own accuracy offline: `client -expected ...` is the acceptance
// test, and it fails the process on any regression.
func compare(w io.Writer, want, got []model.Result) bool {
	if len(want) != len(got) {
		fmt.Fprintf(w, "\nMISMATCH: expected %d results, got %d\n", len(want), len(got))
		return false
	}
	type diff struct {
		idx    int
		column string
		want   string
		got    string
	}
	var diffs []diff
	for i := range want {
		pairs := [][3]string{
			{"protocol", want[i].Protocol, got[i].Protocol},
			{"product", want[i].Product, got[i].Product},
			{"version", want[i].Version, got[i].Version},
			{"os_hint", want[i].OSHint, got[i].OSHint},
		}
		for _, p := range pairs {
			if !strings.EqualFold(strings.TrimSpace(p[1]), strings.TrimSpace(p[2])) {
				diffs = append(diffs, diff{idx: i, column: p[0], want: p[1], got: p[2]})
			}
		}
	}
	if len(diffs) == 0 {
		fmt.Fprintf(w, "\nOK: all %d records match the expected results\n", len(want))
		return true
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "\nMISMATCH (%d field(s))\n", len(diffs))
	fmt.Fprintln(tw, "INDEX\tENDPOINT\tCOLUMN\tWANT\tGOT")
	for _, d := range diffs {
		fmt.Fprintf(tw, "%d\t%s:%d\t%s\t%s\t%s\n",
			d.idx, got[d.idx].IP, got[d.idx].Port, d.column, d.want, d.got)
	}
	_ = tw.Flush()
	return false
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}
