// Package httpclassification correlates HTTP events with trusted operation
// receipts without performing IO or authenticating receipts itself.
//
// Each Classify call must contain events and receipts from ONE authenticated
// Agent/source scope. The caller must verify receipt authenticity and ownership
// before calling this package. A request header, IP address, or User-Agent does
// not establish trust. This package does not change runtime scoring or retain
// state between calls; callers may supply late receipts in a later scoring run.
package httpclassification

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
)

const tolerance = 5 * time.Minute

// time.Parse accepts some non-RFC3339 forms and truncates excess fractional
// precision. Check syntax first so malformed or lossy timestamps cannot bind.
var timestampSyntax = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

// Event is an untrusted raw HTTP event. TS must be an RFC3339 timestamp (with
// optional fractional seconds, up to nanosecond precision). Path is an escaped
// origin-form request target.
type Event struct {
	TS        string `json:"ts"`
	RequestID string `json:"request_id"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
}

// Receipt is an authenticated operation result supplied by the caller. PathHash
// is lowercase SHA256 hex of the exact escaped path, excluding any query. A
// receipt contains no raw resource path, query, credentials, hostname, or user ID.
// TS has the same format as Event.TS.
type Receipt struct {
	TS        string `json:"ts"`
	RequestID string `json:"request_id"`
	Method    string `json:"method"`
	PathHash  string `json:"path_hash"`
	Status    int    `json:"status"`
	Operation string `json:"operation"`
	Outcome   string `json:"outcome"`
}

// Result preserves the input Event. Operation and ResourceHash are populated
// only for an attributed expected, integration_error, or success result.
// Reason is a stable generic code and never contains a raw path.
type Result struct {
	Event        Event
	Kind         string
	Operation    string
	ResourceHash string
	Reason       string
}

type receiptEntry struct {
	receipt  Receipt
	conflict bool
}

// Classify returns one result per event, in input order, without changing either
// input slice. Unattributed 4xx events remain threat; all other unattributed
// events remain other. Only an allowed, bound 2xx success receipt yields success.
//
// Both timestamps must be in the inclusive range [cutoff, now+5 minutes] and
// within 5 minutes of each other. Nonces are exactly 32 lowercase hex digits.
// Repeated raw nonces and conflicting receipts invalidate the nonce even when
// one of those records is malformed or out of the time window. Only byte-for-byte
// equal Receipt values deduplicate; no map iteration chooses a winning receipt.
//
// Rejection reason precedence is invalid_event, reused_nonce, missing_receipt,
// conflicting_receipts, invalid_receipt, binding_mismatch, timestamp_skew, then
// unsupported_outcome. Attributed reasons are matched_expected, matched_error,
// and matched_success.
func Classify(events []Event, receipts []Receipt, now, cutoff time.Time) []Result {
	counts := make(map[string]int, len(events))
	for _, event := range events {
		counts[event.RequestID]++
	}
	byNonce := make(map[string]receiptEntry, len(receipts))
	for _, receipt := range receipts {
		if !lowerHex(receipt.RequestID, 32) {
			continue
		}
		entry, exists := byNonce[receipt.RequestID]
		if !exists {
			byNonce[receipt.RequestID] = receiptEntry{receipt: receipt}
		} else if entry.receipt != receipt {
			entry.conflict = true
			byNonce[receipt.RequestID] = entry
		}
	}

	latest := now.Add(tolerance)
	results := make([]Result, len(events))
	for i, event := range events {
		result := Result{Event: event, Kind: "other"}
		if event.Status >= 400 && event.Status < 500 {
			result.Kind = "threat"
		}
		results[i] = classifyEvent(result, counts[event.RequestID], byNonce, cutoff, latest)
	}
	return results
}

func classifyEvent(result Result, count int, receipts map[string]receiptEntry, cutoff, latest time.Time) Result {
	event := result.Event
	pathHash, validPath := hashPath(event.Path)
	eventTime, validTime := timestamp(event.TS, cutoff, latest)
	if !lowerHex(event.RequestID, 32) || !validPath || !validTime {
		result.Reason = "invalid_event"
		return result
	}
	if count != 1 {
		result.Reason = "reused_nonce"
		return result
	}
	entry, exists := receipts[event.RequestID]
	if !exists {
		result.Reason = "missing_receipt"
		return result
	}
	if entry.conflict {
		result.Reason = "conflicting_receipts"
		return result
	}
	receipt := entry.receipt
	receiptTime, validTime := timestamp(receipt.TS, cutoff, latest)
	if !lowerHex(receipt.PathHash, 64) || !validTime {
		result.Reason = "invalid_receipt"
		return result
	}
	if receipt.Method != event.Method || receipt.Status != event.Status || receipt.PathHash != pathHash {
		result.Reason = "binding_mismatch"
		return result
	}
	if eventTime.Sub(receiptTime) > tolerance || receiptTime.Sub(eventTime) > tolerance {
		result.Reason = "timestamp_skew"
		return result
	}
	kind, reason := allowedOutcome(receipt)
	if kind == "" {
		result.Reason = "unsupported_outcome"
		return result
	}
	result.Kind = kind
	result.Reason = reason
	result.Operation = receipt.Operation
	result.ResourceHash = receipt.PathHash
	return result
}

func allowedOutcome(receipt Receipt) (kind, reason string) {
	var methodOK bool
	switch receipt.Operation {
	case "ensure_collection":
		methodOK = receipt.Method == "MKCOL"
	case "path_exists":
		methodOK = receipt.Method == "PROPFIND"
	case "fetch_file":
		methodOK = receipt.Method == "GET" || receipt.Method == "HEAD"
	case "preview_file":
		methodOK = receipt.Method == "GET"
	}
	if !methodOK {
		return "", ""
	}
	if receipt.Status >= 200 && receipt.Status < 300 && receipt.Outcome == "success" {
		return "success", "matched_success"
	}
	if receipt.Outcome == "expected" &&
		((receipt.Operation == "ensure_collection" && receipt.Status == 405) ||
			(receipt.Operation == "path_exists" && receipt.Status == 404)) {
		return "expected", "matched_expected"
	}
	if receipt.Outcome == "error" && receipt.Status == 404 &&
		(receipt.Operation == "fetch_file" || receipt.Operation == "preview_file") {
		return "integration_error", "matched_error"
	}
	return "", ""
}

func timestamp(value string, cutoff, latest time.Time) (time.Time, bool) {
	if !timestampSyntax.MatchString(value) {
		return time.Time{}, false
	}
	// UTC avoids consulting the process-local timezone or loading its zone file.
	parsed, err := time.ParseInLocation(time.RFC3339Nano, value, time.UTC)
	return parsed, err == nil && !parsed.Before(cutoff) && !parsed.After(latest)
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')) {
			return false
		}
	}
	return true
}

// hashPath validates the escaped origin form, including query escapes, without
// normalizing it. Repeated slashes, dot segments, and percent-escape case remain
// distinct. Query bytes never contribute to the hash. RFC3986 pchar plus slash
// is allowed in the path; the query additionally allows a question mark.
func hashPath(target string) (string, bool) {
	if target == "" || target[0] != '/' {
		return "", false
	}
	path, _, _ := strings.Cut(target, "?")
	for i := 0; i < len(target); i++ {
		c := target[i]
		if c == '?' {
			continue
		}
		if c == '%' {
			if i+2 >= len(target) || !hexDigit(target[i+1]) || !hexDigit(target[i+2]) {
				return "", false
			}
			i += 2
			continue
		}
		if !pathByte(c) {
			return "", false
		}
	}
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:]), true
}

func pathByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || strings.ContainsRune("-._~!$&'()*+,;=:@/", rune(c))
}

func hexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
