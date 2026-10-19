// Package model holds the wire types shared by the server, the client and the
// rule engine.
//
// Nothing in this package knows about any protocol: it only describes the shape
// of a scanner observation and of a fingerprint result. All protocol knowledge
// lives in rules/*.yaml (see the project README).
package model

// Item is one raw observation produced by a network scanner.
type Item struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result is the fingerprint of a single Item.
//
// The JSON field set is part of the public API contract: exactly these seven
// keys, in this order, for every item - identified or not.
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// UnknownProtocol is the only protocol value emitted when no rule has enough
// evidence to name one. Reporting "unknown" is a successful outcome, not an
// error: the service must never fail a batch because one banner is garbage.
const UnknownProtocol = "unknown"

// Unknown returns the conservative answer for an item that no rule recognised.
// Confidence is 0: we have zero confidence in any identification.
func Unknown(it Item) Result {
	return Result{
		IP:         it.IP,
		Port:       it.Port,
		Protocol:   UnknownProtocol,
		Product:    "",
		Version:    "",
		OSHint:     "",
		Confidence: 0,
	}
}
