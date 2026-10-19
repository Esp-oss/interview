package engine

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// fileSchema is the on-disk shape of one rules file. Files are split by protocol
// family purely for readability; the engine merges them into a single ordered
// rule set at load time.
type fileSchema struct {
	Version int     `yaml:"version"`
	Rules   []*Rule `yaml:"rules"`
}

// Load parses every *.yaml file in fsys and returns the merged rules plus a
// human-readable description of the source (used by /health and logs).
//
// Parsing is strict about *field names* (a typo such as "confidance" is an error,
// not a silently ignored key) and permissive about nothing else: a bad rule file
// must fail startup loudly rather than degrade into a service that recognises
// half the protocols.
func Load(fsys fs.FS) ([]*Rule, string, error) {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, "", fmt.Errorf("rules: glob: %w", err)
	}
	if len(names) == 0 {
		return nil, "", errors.New("rules: no *.yaml files found")
	}
	sort.Strings(names)

	all := make([]*Rule, 0, 32)
	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, "", fmt.Errorf("rules: read %s: %w", name, err)
		}
		var schema fileSchema
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if err := dec.Decode(&schema); err != nil {
			if errors.Is(err, io.EOF) {
				continue
			}
			return nil, "", fmt.Errorf("rules: %s: %w", name, err)
		}
		if schema.Version != 1 {
			return nil, "", fmt.Errorf("rules: %s: unsupported schema version %d (want 1)", name, schema.Version)
		}
		for _, r := range schema.Rules {
			if r == nil {
				continue
			}
			r.source = name
		}
		all = append(all, schema.Rules...)
	}
	if len(all) == 0 {
		return nil, "", errors.New("rules: no rules defined")
	}
	return all, fmt.Sprintf("%d files (%s)", len(names), strings.Join(names, ", ")), nil
}
