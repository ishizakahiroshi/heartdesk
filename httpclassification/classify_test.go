package httpclassification_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/httpclassification"
)

var testNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

func digest(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])
}

func fixture() (httpclassification.Event, httpclassification.Receipt) {
	event := httpclassification.Event{
		TS: testNow.Format(time.RFC3339Nano), RequestID: strings.Repeat("a", 32),
		Method: "GET", Path: "/alpha/file.txt", Status: 404,
	}
	receipt := httpclassification.Receipt{
		TS: event.TS, RequestID: event.RequestID, Method: event.Method,
		PathHash: digest(event.Path), Status: event.Status,
		Operation: "fetch_file", Outcome: "error",
	}
	return event, receipt
}

func classify(event httpclassification.Event, receipts ...httpclassification.Receipt) httpclassification.Result {
	return httpclassification.Classify([]httpclassification.Event{event}, receipts, testNow, testNow.Add(-time.Hour))[0]
}

func wantFallback(t *testing.T, result httpclassification.Result, reason string) {
	t.Helper()
	kind := "other"
	if result.Event.Status >= 400 && result.Event.Status < 500 {
		kind = "threat"
	}
	if result.Kind != kind || result.Operation != "" || result.ResourceHash != "" || result.Reason != reason {
		t.Fatalf("unexpected fallback: %+v; want kind %q, reason %q, no attribution", result, kind, reason)
	}
}

func TestAllowedCombinationsAndNearMisses(t *testing.T) {
	// Enumerate every 4xx, each allowed method, method case/unknown near misses,
	// outcome case/unknown near misses, and all 1xx through 5xx status values.
	statuses := []int{-1, 0, 99, 600}
	for status := 100; status < 600; status++ {
		statuses = append(statuses, status)
	}
	for _, operation := range []string{"ensure_collection", "path_exists", "fetch_file", "preview_file", "Fetch_file", "unknown", ""} {
		for _, method := range []string{"MKCOL", "PROPFIND", "GET", "HEAD", "POST", "get", ""} {
			for _, outcome := range []string{"expected", "error", "success", "Success", "unknown", ""} {
				for _, status := range statuses {
					event, receipt := fixture()
					event.Method, receipt.Method = method, method
					event.Status, receipt.Status = status, status
					receipt.Operation, receipt.Outcome = operation, outcome
					want := "other"
					if status >= 400 && status < 500 {
						want = "threat"
					}
					allowedMethod := map[string][]string{
						"ensure_collection": {"MKCOL"}, "path_exists": {"PROPFIND"},
						"fetch_file": {"GET", "HEAD"}, "preview_file": {"GET"},
					}
					for _, allowed := range allowedMethod[operation] {
						if allowed != method {
							continue
						}
						if status >= 200 && status < 300 && outcome == "success" {
							want = "success"
						}
						if outcome == "expected" && ((operation == "ensure_collection" && status == 405) || (operation == "path_exists" && status == 404)) {
							want = "expected"
						}
						if outcome == "error" && status == 404 && (operation == "fetch_file" || operation == "preview_file") {
							want = "integration_error"
						}
					}
					got := classify(event, receipt)
					if got.Kind != want || got.Event != event {
						t.Fatalf("%s %s %d %s: got %+v, want %s", operation, method, status, outcome, got, want)
					}
					if want == "threat" || want == "other" {
						wantFallback(t, got, "unsupported_outcome")
					} else {
						reason := map[string]string{"expected": "matched_expected", "integration_error": "matched_error", "success": "matched_success"}[want]
						if got.Operation != operation || got.ResourceHash != receipt.PathHash || got.Reason != reason {
							t.Fatalf("missing attribution: %+v", got)
						}
					}
				}
			}
		}
	}
}

func TestBindingNegativeControls(t *testing.T) {
	event, receipt := fixture()
	if got := classify(event, receipt); got.Kind != "integration_error" {
		t.Fatalf("positive control: %+v", got)
	}
	tests := []struct {
		name   string
		change func(*httpclassification.Event, *httpclassification.Receipt)
		reason string
	}{
		{"event nonce", func(e *httpclassification.Event, _ *httpclassification.Receipt) { e.RequestID = strings.Repeat("b", 32) }, "missing_receipt"},
		{"receipt nonce", func(_ *httpclassification.Event, r *httpclassification.Receipt) { r.RequestID = strings.Repeat("b", 32) }, "missing_receipt"},
		{"event method", func(e *httpclassification.Event, _ *httpclassification.Receipt) { e.Method = "HEAD" }, "binding_mismatch"},
		{"receipt method", func(_ *httpclassification.Event, r *httpclassification.Receipt) { r.Method = "HEAD" }, "binding_mismatch"},
		{"event path", func(e *httpclassification.Event, _ *httpclassification.Receipt) { e.Path = "/alpha/other.txt" }, "binding_mismatch"},
		{"receipt path hash", func(_ *httpclassification.Event, r *httpclassification.Receipt) { r.PathHash = digest("/alpha/other.txt") }, "binding_mismatch"},
		{"event status", func(e *httpclassification.Event, _ *httpclassification.Receipt) { e.Status = 405 }, "binding_mismatch"},
		{"receipt status", func(_ *httpclassification.Event, r *httpclassification.Receipt) { r.Status = 405 }, "binding_mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, r := event, receipt
			test.change(&e, &r)
			wantFallback(t, classify(e, r), test.reason)
		})
	}
}

func TestLowercaseIdentifiers(t *testing.T) {
	for _, nonce := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("a", 31) + " ", strings.Repeat("a", 30) + "é"} {
		event, receipt := fixture()
		event.RequestID, receipt.RequestID = nonce, nonce
		wantFallback(t, classify(event, receipt), "invalid_event")
	}
	for _, hash := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63) + "\n"} {
		event, receipt := fixture()
		receipt.PathHash = hash
		wantFallback(t, classify(event, receipt), "invalid_receipt")
	}
	event, receipt := fixture()
	receipt.RequestID = strings.ToUpper(receipt.RequestID)
	// An uppercase receipt nonce is not silently normalized into the raw nonce.
	known := classify(event, receipt)
	wantFallback(t, known, "missing_receipt")
}

func TestExactEscapedPathAndQueryStripping(t *testing.T) {
	paths := []string{"/", "/alpha/file.txt", "/alpha/a%2Fb", "/alpha/a%2fb", "/alpha/a/b", "/alpha/./b", "/alpha/../b", "/alpha//b", "//alpha/b", "/alpha/%252F", "/alpha/%E3%81%82", "/alpha/a%3Fb%23c", "/alpha/-._~!$&'()*+,;=:@"}
	queries := []string{"", "?", "?mode=small", "?next=/alpha/a%2Fb&mode=large?again", "?q=%23%25"}
	for _, path := range paths {
		for _, query := range queries {
			event, receipt := fixture()
			event.Path, receipt.PathHash = path+query, digest(path)
			if got := classify(event, receipt); got.Kind != "integration_error" || got.ResourceHash != digest(path) {
				t.Fatalf("exact path %q with query %q: %+v", path, query, got)
			}
		}
	}
	for _, pair := range [][2]string{{"/alpha/a%2Fb", "/alpha/a/b"}, {"/alpha/a%2fb", "/alpha/a%2Fb"}, {"/alpha/./b", "/alpha/b"}, {"/alpha/../b", "/b"}, {"/alpha//b", "/alpha/b"}, {"/alpha/%41", "/alpha/A"}} {
		event, receipt := fixture()
		event.Path, receipt.PathHash = pair[0], digest(pair[1])
		wantFallback(t, classify(event, receipt), "binding_mismatch")
	}
}

func TestRejectMalformedPaths(t *testing.T) {
	for _, path := range []string{"", "alpha/file", "*", "https://example.com/alpha/file", "https://203.0.113.1/alpha/file", "example.com:443", "/alpha/file#fragment", "/alpha/file?x=1#fragment", "/alpha/%", "/alpha/%0", "/alpha/%gg", "/alpha/file?x=%", "/alpha/file?x=%0g", "/alpha/a b", "/alpha/a\tb", "/alpha/a\nb", "/alpha/a\x00b", "/alpha/a\x7fb", "/alpha/a\\b", "/alpha/あ", "/alpha/<file>", "/alpha/[file]"} {
		t.Run(fmt.Sprintf("%q", path), func(t *testing.T) {
			event, receipt := fixture()
			event.Path, receipt.PathHash = path, digest(strings.SplitN(path, "?", 2)[0])
			wantFallback(t, classify(event, receipt), "invalid_event")
		})
	}
}

func TestTimestampBoundsAndSkew(t *testing.T) {
	cutoff := testNow.Add(-time.Hour)
	latest := testNow.Add(5 * time.Minute)
	tests := []struct {
		name      string
		eventTS   time.Time
		receiptTS time.Time
		reason    string
	}{
		{"cutoff inclusive", cutoff, cutoff, "matched_error"},
		{"future inclusive", latest, latest, "matched_error"},
		{"event before cutoff", cutoff.Add(-time.Nanosecond), cutoff, "invalid_event"},
		{"receipt before cutoff", cutoff, cutoff.Add(-time.Nanosecond), "invalid_receipt"},
		{"event after future limit", latest.Add(time.Nanosecond), latest, "invalid_event"},
		{"receipt after future limit", latest, latest.Add(time.Nanosecond), "invalid_receipt"},
		{"event newer at skew", testNow, testNow.Add(-5 * time.Minute), "matched_error"},
		{"receipt newer at skew", testNow, latest, "matched_error"},
		{"event newer beyond skew", testNow, testNow.Add(-5*time.Minute - time.Nanosecond), "timestamp_skew"},
		{"receipt newer beyond skew", testNow.Add(-time.Nanosecond), latest, "timestamp_skew"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event, receipt := fixture()
			event.TS = test.eventTS.Format(time.RFC3339Nano)
			receipt.TS = test.receiptTS.Format(time.RFC3339Nano)
			got := classify(event, receipt)
			if test.reason == "matched_error" {
				if got.Kind != "integration_error" || got.Reason != test.reason {
					t.Fatalf("boundary should match: %+v", got)
				}
			} else {
				wantFallback(t, got, test.reason)
			}
		})
	}
	for _, badTS := range []string{
		"", "invalid", "2026-10-30", "2026-10-30T12:00:00", "2026-10-30T12:00:00Z ",
		"2026-13-30T12:00:00Z", "2026-10-30T12:00:00Z\n", "2026-10-30t12:00:00z",
		"2026-10-31T12:00:00+24:00", "2026-10-29T12:00:00-24:00",
		"2026-10-30T13:00:00+00:60", "2026-10-30T11:00:00-00:60",
		"2026-10-30T1:00:00-11:00", "2026-10-30T12:00:00,0Z",
		"2026-10-30T12:00:00.Z", "2026-10-30T12:00:00.0000000001Z",
		"2026-10-30T24:00:00Z", "2026-10-30T12:60:00Z", "2026-02-30T12:00:00Z",
	} {
		event, receipt := fixture()
		event.TS = badTS
		wantFallback(t, classify(event, receipt), "invalid_event")
		event, receipt = fixture()
		receipt.TS = badTS
		wantFallback(t, classify(event, receipt), "invalid_receipt")
	}
	event, receipt := fixture()
	receipt.TS = testNow.In(time.FixedZone("synthetic", 2*60*60)).Format(time.RFC3339Nano)
	if got := classify(event, receipt); got.Kind != "integration_error" {
		t.Fatalf("equal instant with offset: %+v", got)
	}
	got := httpclassification.Classify([]httpclassification.Event{event}, []httpclassification.Receipt{receipt}, testNow, latest.Add(time.Nanosecond))[0]
	wantFallback(t, got, "invalid_event")
}

func TestDuplicateAndConflictingReceipts(t *testing.T) {
	event, receipt := fixture()
	if got := classify(event, receipt, receipt, receipt); got.Kind != "integration_error" {
		t.Fatalf("exact duplicates should deduplicate: %+v", got)
	}
	changes := []func(*httpclassification.Receipt){
		func(r *httpclassification.Receipt) { r.TS = testNow.Add(time.Second).Format(time.RFC3339Nano) },
		func(r *httpclassification.Receipt) { r.TS = testNow.Add(-2 * time.Hour).Format(time.RFC3339Nano) },
		func(r *httpclassification.Receipt) { r.TS = testNow.Add(time.Hour).Format(time.RFC3339Nano) },
		func(r *httpclassification.Receipt) { r.TS = "invalid" },
		func(r *httpclassification.Receipt) { r.Method = "HEAD" },
		func(r *httpclassification.Receipt) { r.PathHash = digest("/alpha/other.txt") },
		func(r *httpclassification.Receipt) { r.PathHash = "invalid" },
		func(r *httpclassification.Receipt) { r.Status = 200 },
		func(r *httpclassification.Receipt) { r.Operation = "preview_file" },
		func(r *httpclassification.Receipt) { r.Operation = "unknown" },
		func(r *httpclassification.Receipt) { r.Outcome = "expected" },
	}
	for _, change := range changes {
		conflict := receipt
		change(&conflict)
		for _, receipts := range [][]httpclassification.Receipt{{receipt, conflict}, {conflict, receipt}, {receipt, conflict, receipt}, {conflict, receipt, conflict}} {
			wantFallback(t, classify(event, receipts...), "conflicting_receipts")
		}
	}
}

func TestRawNonceReuseInvalidatesBothEvents(t *testing.T) {
	event, receipt := fixture()
	changes := []func(*httpclassification.Event){
		func(_ *httpclassification.Event) {},
		func(e *httpclassification.Event) { e.Path = "/alpha/other.txt" },
		func(e *httpclassification.Event) { e.Method = "HEAD" },
		func(e *httpclassification.Event) { e.Status = 200 },
		func(e *httpclassification.Event) { e.TS = testNow.Add(-2 * time.Hour).Format(time.RFC3339Nano) },
		func(e *httpclassification.Event) { e.Path = "invalid" },
	}
	for _, change := range changes {
		second := event
		change(&second)
		for _, events := range [][]httpclassification.Event{{event, second}, {second, event}} {
			got := httpclassification.Classify(events, []httpclassification.Receipt{receipt}, testNow, testNow.Add(-time.Hour))
			for i, result := range got {
				if result.Event != events[i] || result.Kind == "integration_error" || result.Kind == "success" || result.Kind == "expected" || result.Operation != "" || result.ResourceHash != "" {
					t.Fatalf("reused nonce attributed or reordered: %+v", got)
				}
				if events[i] == event {
					wantFallback(t, result, "reused_nonce")
				}
			}
		}
	}
}

func TestMissingReceiptLegacyAndSpoofedHeader(t *testing.T) {
	for _, raw := range []string{
		`{"ts":"2026-10-30T12:00:00Z","path":"/alpha/file.txt","status":404}`,
		`{"ts":"2026-10-30T12:00:00Z","request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","method":"GET","path":"/alpha/file.txt","status":404,"ip":"203.0.113.1","user_agent":"synthetic","X-HTTP-Operation-ID":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
	} {
		var event httpclassification.Event
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			t.Fatal(err)
		}
		got := classify(event)
		if got.Kind != "threat" || got.Operation != "" || got.ResourceHash != "" {
			t.Fatalf("old or spoofed event gained trust: %+v", got)
		}
	}
	for _, status := range []int{199, 200, 204, 299, 300, 400, 401, 403, 404, 499, 500} {
		event, _ := fixture()
		event.Status = status
		wantFallback(t, classify(event), "missing_receipt")
	}
}

func TestSuccessRecoveryAndLateReceipt(t *testing.T) {
	failed, failure := fixture()
	succeeded, success := failed, failure
	succeeded.RequestID, success.RequestID = strings.Repeat("b", 32), strings.Repeat("b", 32)
	succeeded.Status, success.Status = 200, 200
	success.Outcome = "success"
	events := []httpclassification.Event{failed, succeeded}
	without := httpclassification.Classify(events, nil, testNow, testNow.Add(-time.Hour))
	if without[0].Kind != "threat" || without[1].Kind != "other" {
		t.Fatalf("unmatched inputs: %+v", without)
	}
	with := httpclassification.Classify(events, []httpclassification.Receipt{success, failure}, testNow, testNow.Add(-time.Hour))
	if with[0].Kind != "integration_error" || with[1].Kind != "success" || with[0].ResourceHash != with[1].ResourceHash {
		t.Fatalf("late receipts should provide failure and recovery evidence separately: %+v", with)
	}
}

func TestInputImmutabilityAndDeterministicOrder(t *testing.T) {
	events := make([]httpclassification.Event, 6)
	receipts := make([]httpclassification.Receipt, 6)
	for i := range events {
		events[i], receipts[i] = fixture()
		events[i].RequestID = fmt.Sprintf("%032x", i)
		receipts[i].RequestID = events[i].RequestID
		events[i].Path = fmt.Sprintf("/alpha/file-%d.txt?mode=small", i)
		receipts[i].PathHash = digest(fmt.Sprintf("/alpha/file-%d.txt", i))
	}
	events[1].Status, receipts[1].Status = 200, 200
	receipts[1].Outcome = "success"
	receipts[2].Operation = "unknown"
	events[3].RequestID = events[4].RequestID
	conflict := receipts[5]
	conflict.Outcome = "expected"
	receipts = append(receipts, conflict, receipts[0])
	beforeEvents := append([]httpclassification.Event(nil), events...)
	beforeReceipts := append([]httpclassification.Receipt(nil), receipts...)
	want := httpclassification.Classify(events, receipts, testNow, testNow.Add(-time.Hour))
	for repeat := 0; repeat < 32; repeat++ {
		got := httpclassification.Classify(events, receipts, testNow, testNow.Add(-time.Hour))
		if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(events, beforeEvents) || !reflect.DeepEqual(receipts, beforeReceipts) {
			t.Fatal("nondeterministic results or mutated input")
		}
	}
	for left, right := 0, len(receipts)-1; left < right; left, right = left+1, right-1 {
		receipts[left], receipts[right] = receipts[right], receipts[left]
	}
	if got := httpclassification.Classify(events, receipts, testNow, testNow.Add(-time.Hour)); !reflect.DeepEqual(got, want) {
		t.Fatal("receipt order selected a different result")
	}
	for i, result := range want {
		if result.Event != events[i] || strings.Contains(result.Reason, "/alpha/") {
			t.Fatalf("event order or generic reason violated: %+v", result)
		}
	}
	if got := httpclassification.Classify(nil, receipts, testNow, testNow); len(got) != 0 {
		t.Fatalf("empty events returned results: %+v", got)
	}
}

func TestWireFields(t *testing.T) {
	event, receipt := fixture()
	for _, test := range []struct {
		value any
		keys  []string
	}{
		{event, []string{"ts", "request_id", "method", "path", "status"}},
		{receipt, []string{"ts", "request_id", "method", "path_hash", "status", "operation", "outcome"}},
	} {
		encoded, err := json.Marshal(test.value)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		if len(fields) != len(test.keys) {
			t.Fatalf("unexpected wire fields: %s", encoded)
		}
		for _, key := range test.keys {
			if _, ok := fields[key]; !ok {
				t.Fatalf("missing wire field %q: %s", key, encoded)
			}
		}
	}
}
