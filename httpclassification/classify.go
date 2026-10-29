// Package httpclassification decides, per raw HTTP access event, whether the
// event is explained by a trusted receipt written by the integration that made
// the request (policy v2).
//
// The package is pure: no file, network or clock access. Callers pass the raw
// events and the receipts they have at that moment and get one Result per raw
// event. Receipts may arrive after the raw events, so callers recompute the
// classification each time over the data they have; nothing is cached here.
//
// Anything that is not an exact one-to-one match stays Unclassified, and an
// Unclassified event keeps being scored by the caller exactly as before.
package httpclassification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MatchWindow is the largest allowed difference between the raw event time and
// the receipt time.
const MatchWindow = 5 * time.Minute

// Class is the classification of one raw event.
type Class int

const (
	// Unclassified: no trusted explanation. The caller keeps scoring it.
	Unclassified Class = iota
	// Expected: the receipt says this exact status is part of the normal flow
	// (for example MKCOL on an existing collection). Not scored, but counted.
	Expected
	// IntegrationError: the receipt says the integration itself failed
	// (for example GET of a file that should exist). Not scored as an attack,
	// counted separately and reported by the integration_http_error alert.
	IntegrationError
	// Success: a matched receipt with a 2xx status. Used for recovery only.
	Success
)

func (c Class) String() string {
	switch c {
	case Expected:
		return "expected"
	case IntegrationError:
		return "integration_error"
	case Success:
		return "success"
	default:
		return "unclassified"
	}
}

// Operation names written by the producer.
const (
	OpEnsureCollection = "ensure_collection"
	OpPathExists       = "path_exists"
	OpFetchFile        = "fetch_file"
	OpPreviewFile      = "preview_file"
)

// RawEvent is one access-log event. Scope identifies the agent/source the
// event came from; a receipt only matches events with the same Scope.
type RawEvent struct {
	Scope     string
	RequestID string
	Method    string
	// Path is the exact escaped request path. A query string, if present, is
	// ignored. The path is never unescaped or normalized.
	Path   string
	Status int
	Time   time.Time
}

// Receipt is one trusted receipt written by the integration.
type Receipt struct {
	Scope     string
	Time      time.Time
	RequestID string
	Method    string
	PathHash  string
	Status    int
	Operation string
	Outcome   string
}

// Result is the classification of the raw event at the same index.
type Result struct {
	Class     Class
	Operation string
	PathHash  string
	// Reason is a stable generic code (never contains a path or any input
	// text) saying why the event is, or is not, classified.
	Reason string
}

var (
	reRequestID = regexp.MustCompile(`^[0-9a-f]{32}$`)
	rePathHash  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// PathHash returns the lowercase hex sha256 of the exact escaped path with any
// query string removed. It does not unescape or normalize.
func PathHash(escapedPath string) string {
	if i := strings.IndexByte(escapedPath, '?'); i >= 0 {
		escapedPath = escapedPath[:i]
	}
	sum := sha256.Sum256([]byte(escapedPath))
	return hex.EncodeToString(sum[:])
}

// ValidRequestID reports whether s is a lowercase hex32 request id.
func ValidRequestID(s string) bool { return reRequestID.MatchString(s) }

// policyOutcome returns the outcome the policy assigns to (operation, method,
// status), or "" when the combination is not covered. The receipt's own
// outcome is only checked for consistency with this; it never decides.
func policyOutcome(op, method string, status int) (Class, string) {
	if status >= 200 && status < 300 {
		// Only the method that operation really uses counts as success evidence.
		switch {
		case op == OpEnsureCollection && method == "MKCOL",
			op == OpPathExists && method == "PROPFIND",
			op == OpFetchFile && (method == "GET" || method == "HEAD"),
			op == OpPreviewFile && method == "GET":
			return Success, "success"
		}
		return Unclassified, ""
	}
	switch op {
	case OpEnsureCollection:
		if method == "MKCOL" && status == 405 {
			return Expected, "expected"
		}
	case OpPathExists:
		if method == "PROPFIND" && status == 404 {
			return Expected, "expected"
		}
	case OpFetchFile:
		if (method == "GET" || method == "HEAD") && status == 404 {
			return IntegrationError, "integration_error"
		}
	case OpPreviewFile:
		if method == "GET" && status == 404 {
			return IntegrationError, "integration_error"
		}
	}
	return Unclassified, ""
}

type key struct{ scope, id string }

// Classify returns one Result per raw event (same order). An event is
// classified only when exactly one raw event and exactly one receipt carry its
// (scope, request_id), the receipt is well formed and agrees on method, path
// hash and status, the times are within MatchWindow, and the policy table
// covers the (operation, method, status). Everything else is Unclassified.
func Classify(raw []RawEvent, receipts []Receipt) []Result {
	out := make([]Result, len(raw))

	rawCount := make(map[key]int, len(raw))
	for _, e := range raw {
		if ValidRequestID(e.RequestID) {
			rawCount[key{e.Scope, e.RequestID}]++
		}
	}
	// Receipts are counted by request id even when otherwise malformed, so a
	// malformed twin also disables the match instead of being ignored.
	rcCount := make(map[key]int, len(receipts))
	rcIndex := make(map[key]int, len(receipts))
	for i, r := range receipts {
		k := key{r.Scope, r.RequestID}
		rcCount[k]++
		rcIndex[k] = i
	}

	for i, e := range raw {
		out[i].Reason = classifyOne(e, rawCount, rcCount, rcIndex, receipts, &out[i])
	}
	return out
}

// ValidEscapedPath reports whether s is an origin-form request target: it
// starts with a single "/", has no fragment, no control or blank bytes and only
// well-formed %XX escapes. A query string is allowed (and ignored by PathHash).
func ValidEscapedPath(s string) bool {
	if len(s) == 0 || s[0] != '/' || strings.HasPrefix(s, "//") || strings.IndexByte(s, '#') >= 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f {
			return false
		}
		if c == '%' {
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return false
			}
			i += 2
		}
	}
	return true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func classifyOne(e RawEvent, rawCount, rcCount map[key]int, rcIndex map[key]int, receipts []Receipt, res *Result) string {
	if !ValidRequestID(e.RequestID) {
		return "no_request_id"
	}
	k := key{e.Scope, e.RequestID}
	if rawCount[k] != 1 {
		return "duplicate_request_id"
	}
	switch rcCount[k] {
	case 0:
		return "no_receipt"
	case 1:
	default:
		return "ambiguous_receipt"
	}
	r := receipts[rcIndex[k]]
	if !wellFormed(r) {
		return "receipt_malformed"
	}
	if !ValidEscapedPath(e.Path) {
		return "invalid_path"
	}
	method := strings.ToUpper(e.Method)
	if e.Method == "" || method != e.Method || r.Method != method ||
		r.Status != e.Status || r.PathHash != PathHash(e.Path) {
		return "binding_mismatch"
	}
	if e.Time.IsZero() || r.Time.IsZero() {
		return "time_invalid"
	}
	d := e.Time.Sub(r.Time)
	if d < 0 {
		d = -d
	}
	if d > MatchWindow {
		return "time_skew"
	}
	class, outcome := policyOutcome(r.Operation, method, e.Status)
	if class == Unclassified {
		return "policy_not_covered"
	}
	if r.Outcome != outcome {
		return "outcome_mismatch"
	}
	*res = Result{Class: class, Operation: r.Operation, PathHash: r.PathHash}
	return "matched"
}
func wellFormed(r Receipt) bool {
	return ValidRequestID(r.RequestID) && rePathHash.MatchString(r.PathHash) &&
		r.Method != "" && r.Status > 0 && r.Operation != "" && r.Outcome != ""
}

type receiptJSON struct {
	TS        string          `json:"ts"`
	RequestID string          `json:"request_id"`
	Method    string          `json:"method"`
	PathHash  string          `json:"path_hash"`
	Status    json.RawMessage `json:"status"`
	Operation string          `json:"operation"`
	Outcome   string          `json:"outcome"`
}

// ParseReceipt parses one receipt JSON object. parseTime converts the "ts"
// string to a time (callers pass their own tolerant parser). ok is false only
// when the line is not a JSON object. A receipt whose ts or status is
// unusable is still returned (zero time / zero status) so that it counts as a
// duplicate of its request id; Classify never matches it.
func ParseReceipt(line []byte, scope string, parseTime func(string) (time.Time, error)) (Receipt, bool) {
	var j receiptJSON
	if err := json.Unmarshal(line, &j); err != nil {
		return Receipt{}, false
	}
	var t time.Time
	if tt, err := parseTime(j.TS); err == nil {
		t = tt
	}
	status, _ := strconv.ParseInt(strings.TrimSpace(string(j.Status)), 10, 32)
	return Receipt{
		Scope: scope, Time: t, RequestID: j.RequestID,
		Method: j.Method, PathHash: j.PathHash, Status: int(status),
		Operation: j.Operation, Outcome: j.Outcome,
	}, true
}
