// Package rules is the fingerprint corpus.
//
// The YAML files next to this file are the *entire* protocol knowledge of the
// system: protocol names, product names, version patterns, OS tokens and
// confidence scores. No Go source file names a protocol or a product.
//
// Two delivery modes are supported on purpose:
//
//   - The files are embedded into the server binary at build time, so a
//     `scratch` container needs no shell, no filesystem and no volume to work.
//   - At run time, setting RULES_DIR replaces the embedded set with a mounted
//     directory. That is how an operator adds a fingerprint without rebuilding
//     the image.
package rules

import "embed"

// Embedded holds the default rule set compiled into the binary.
//
//go:embed *.yaml
var Embedded embed.FS
