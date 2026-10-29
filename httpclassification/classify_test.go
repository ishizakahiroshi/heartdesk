package httpclassification

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)

const (
	id1  = "0123456789abcdef0123456789abcdef"
	id2  = "fedcba9876543210fedcba9876543210"
	path = "/nextcloud/remote.php/dav/files/alice/folder%20a/"
)

func pair(method string, status int, op, outcome string) (RawEvent, Receipt) {
	return RawEvent{Scope: "agent-a", RequestID: id1, Method: method, Path: path + "?x=1", Status: status, Time: t0},
		Receipt{Scope: "agent-a", Time: t0.Add(time.Second), RequestID: id1, Method: method, PathHash: PathHash(path), Status: status, Operation: op, Outcome: outcome}
}

func one(t *testing.T, raw RawEvent, rc ...Receipt) Result {
	t.Helper()
	res := Classify([]RawEvent{raw}, rc)
	if len(res) != 1 {
		t.Fatalf("len=%d", len(res))
	}
	return res[0]
}

func TestPolicyTable(t *testing.T) {
	cases := []struct {
		method string
		status int
		op     string
		outc   string
		want   Class
	}{
		{"MKCOL", 405, OpEnsureCollection, "expected", Expected},
		{"PROPFIND", 404, OpPathExists, "expected", Expected},
		{"GET", 404, OpFetchFile, "integration_error", IntegrationError},
		{"HEAD", 404, OpFetchFile, "integration_error", IntegrationError},
		{"GET", 404, OpPreviewFile, "integration_error", IntegrationError},
		{"MKCOL", 201, OpEnsureCollection, "success", Success},
		{"GET", 200, OpFetchFile, "success", Success},
		// not covered by the policy
		{"MKCOL", 404, OpEnsureCollection, "expected", Unclassified},
		{"PROPFIND", 405, OpPathExists, "expected", Unclassified},
		{"MKCOL", 403, OpEnsureCollection, "expected", Unclassified},
		{"GET", 401, OpFetchFile, "integration_error", Unclassified},
		{"GET", 403, OpFetchFile, "integration_error", Unclassified},
		{"HEAD", 404, OpPreviewFile, "integration_error", Unclassified},
		{"GET", 404, "delete_everything", "expected", Unclassified},
		// receipt outcome disagrees with the policy
		{"MKCOL", 405, OpEnsureCollection, "integration_error", Unclassified},
		{"GET", 404, OpFetchFile, "expected", Unclassified},
	}
	for _, c := range cases {
		raw, rc := pair(c.method, c.status, c.op, c.outc)
		if got := one(t, raw, rc).Class; got != c.want {
			t.Errorf("%s %d %s/%s: got %v want %v", c.method, c.status, c.op, c.outc, got, c.want)
		}
	}
}

func TestMatchReportsOperationAndHash(t *testing.T) {
	raw, rc := pair("MKCOL", 405, OpEnsureCollection, "expected")
	r := one(t, raw, rc)
	if r.Operation != OpEnsureCollection || r.PathHash != PathHash(path) {
		t.Fatalf("%+v", r)
	}
}

func TestNoMatchStaysUnclassified(t *testing.T) {
	raw, rc := pair("MKCOL", 405, OpEnsureCollection, "expected")
	if one(t, raw).Class != Unclassified {
		t.Error("no receipt must stay unclassified")
	}
	mut := map[string]func(*RawEvent, *Receipt){
		"other scope":     func(_ *RawEvent, r *Receipt) { r.Scope = "agent-b" },
		"other id":        func(_ *RawEvent, r *Receipt) { r.RequestID = id2 },
		"other method":    func(_ *RawEvent, r *Receipt) { r.Method = "PROPFIND" },
		"other path":      func(e *RawEvent, _ *Receipt) { e.Path = path + "x" },
		"unescaped path":  func(e *RawEvent, _ *Receipt) { e.Path = "/nextcloud/remote.php/dav/files/alice/folder a/" },
		"other status":    func(e *RawEvent, _ *Receipt) { e.Status = 404 },
		"late receipt":    func(_ *RawEvent, r *Receipt) { r.Time = t0.Add(MatchWindow + time.Second) },
		"early receipt":   func(_ *RawEvent, r *Receipt) { r.Time = t0.Add(-MatchWindow - time.Second) },
		"zero receipt ts": func(_ *RawEvent, r *Receipt) { r.Time = time.Time{} },
		"bad id case":     func(e *RawEvent, r *Receipt) { e.RequestID = strings.ToUpper(id1); r.RequestID = e.RequestID },
		"short id":        func(e *RawEvent, r *Receipt) { e.RequestID = "abc"; r.RequestID = "abc" },
		"bad hash":        func(_ *RawEvent, r *Receipt) { r.PathHash = "zz" },
		"lower method":    func(e *RawEvent, r *Receipt) { e.Method = "mkcol"; r.Method = "mkcol" },
		"empty op":        func(_ *RawEvent, r *Receipt) { r.Operation = "" },
	}
	for name, f := range mut {
		e, r := raw, rc
		f(&e, &r)
		if got := one(t, e, r).Class; got != Unclassified {
			t.Errorf("%s: got %v", name, got)
		}
	}
	// boundary: exactly the window is allowed
	e, r := raw, rc
	r.Time = t0.Add(MatchWindow)
	if one(t, e, r).Class != Expected {
		t.Error("exactly 5 minutes must match")
	}
	r.Time = t0.Add(-MatchWindow)
	if one(t, e, r).Class != Expected {
		t.Error("exactly -5 minutes must match")
	}
}

func TestDuplicatesDisableMatch(t *testing.T) {
	raw, rc := pair("MKCOL", 405, OpEnsureCollection, "expected")
	res := Classify([]RawEvent{raw}, []Receipt{rc, rc})
	if res[0].Class != Unclassified {
		t.Error("duplicate receipt must not classify")
	}
	// a malformed twin also counts as a duplicate
	bad := rc
	bad.PathHash = ""
	if Classify([]RawEvent{raw}, []Receipt{rc, bad})[0].Class != Unclassified {
		t.Error("malformed twin receipt must not classify")
	}
	// duplicate raw request id: neither raw event is classified
	res = Classify([]RawEvent{raw, raw}, []Receipt{rc})
	if res[0].Class != Unclassified || res[1].Class != Unclassified {
		t.Error("duplicate raw request id must not classify")
	}
	// a same id in another scope is independent
	other := raw
	other.Scope = "agent-b"
	res = Classify([]RawEvent{raw, other}, []Receipt{rc})
	if res[0].Class != Expected || res[1].Class != Unclassified {
		t.Errorf("scope isolation: %+v", res)
	}
}

func TestLateReceiptRecompute(t *testing.T) {
	raw, rc := pair("PROPFIND", 404, OpPathExists, "expected")
	if Classify([]RawEvent{raw}, nil)[0].Class != Unclassified {
		t.Fatal("before the receipt arrives the event is scored")
	}
	if Classify([]RawEvent{raw}, []Receipt{rc})[0].Class != Expected {
		t.Fatal("after the receipt arrives the event is expected")
	}
}

func TestEventWithoutRequestIDUnchanged(t *testing.T) {
	raw, rc := pair("MKCOL", 405, OpEnsureCollection, "expected")
	raw.RequestID = ""
	rc.RequestID = ""
	if one(t, raw, rc).Class != Unclassified {
		t.Error("empty request id must not match an empty receipt id")
	}
}

func TestParseReceipt(t *testing.T) {
	pt := func(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }
	line := `{"ts":"2026-10-30T10:00:01Z","request_id":"` + id1 + `","method":"MKCOL","path_hash":"` + PathHash(path) + `","status":405,"operation":"ensure_collection","outcome":"expected"}`
	r, ok := ParseReceipt([]byte(line), "agent-a", pt)
	if !ok || r.Status != 405 || r.Scope != "agent-a" || r.Time.IsZero() {
		t.Fatalf("%+v ok=%v", r, ok)
	}
	if _, ok := ParseReceipt([]byte("not json"), "a", pt); ok {
		t.Error("garbage must fail")
	}
	r, ok = ParseReceipt([]byte(`{"ts":"x","request_id":"`+id1+`","status":"abc"}`), "a", pt)
	if !ok || !r.Time.IsZero() || r.Status != 0 {
		t.Errorf("unusable fields must be zero: %+v", r)
	}
}

func TestPathHashIgnoresQueryOnly(t *testing.T) {
	if PathHash("/a?b=1") != PathHash("/a") {
		t.Error("query must be ignored")
	}
	if PathHash("/a%20b") == PathHash("/a b") {
		t.Error("escaped path must not be normalized")
	}
}

func TestSuccessNeedsTheOperationsMethod(t *testing.T) {
	bad := []struct {
		method string
		op     string
	}{
		{"GET", OpEnsureCollection}, {"PUT", OpEnsureCollection}, {"GET", OpPathExists},
		{"PROPFIND", OpFetchFile}, {"HEAD", OpPreviewFile}, {"POST", OpFetchFile},
	}
	for _, c := range bad {
		raw, rc := pair(c.method, 200, c.op, "success")
		if got := one(t, raw, rc).Class; got != Unclassified {
			t.Errorf("%s 200 %s: got %v", c.method, c.op, got)
		}
	}
	raw, rc := pair("HEAD", 200, OpFetchFile, "success")
	if one(t, raw, rc).Class != Success {
		t.Error("HEAD 200 fetch_file must be success")
	}
}

func TestValidEscapedPath(t *testing.T) {
	good := []string{"/", "/a/b%20c", "/a?x=1", "/a%2F%2f", "/nextcloud/remote.php/dav/files/alice/"}
	bad := []string{"", "a/b", "//host/x", "http://example.com/x", "/a#frag", "/a?x#y", "/a%2", "/a%zz", "/a b", "/a\x00", "/a\n", "/é"}
	for _, s := range good {
		if !ValidEscapedPath(s) {
			t.Errorf("should be valid: %q", s)
		}
	}
	for _, s := range bad {
		if ValidEscapedPath(s) {
			t.Errorf("should be invalid: %q", s)
		}
	}
	// an otherwise perfect pair with an invalid path never matches
	raw, rc := pair("MKCOL", 405, OpEnsureCollection, "expected")
	raw.Path = "/a%zz"
	rc.PathHash = PathHash(raw.Path)
	if r := one(t, raw, rc); r.Class != Unclassified || r.Reason != "invalid_path" {
		t.Errorf("%+v", r)
	}
}

func TestReasonCodesAreGenericAndInputsAreUntouched(t *testing.T) {
	raw, rc := pair("MKCOL", 405, OpEnsureCollection, "expected")
	raws, rcs := []RawEvent{raw}, []Receipt{rc}
	rawCopy, rcCopy := raws[0], rcs[0]
	if r := Classify(raws, rcs)[0]; r.Reason != "matched" {
		t.Fatalf("%+v", r)
	}
	if raws[0] != rawCopy || rcs[0] != rcCopy {
		t.Fatal("inputs were modified")
	}
	if r := Classify(raws, nil)[0]; r.Reason != "no_receipt" {
		t.Fatalf("%+v", r)
	}
	// negative control: changing exactly one binding field breaks the match
	for name, f := range map[string]func(*RawEvent){
		"method": func(e *RawEvent) { e.Method = "PROPFIND" },
		"status": func(e *RawEvent) { e.Status = 404 },
		"path":   func(e *RawEvent) { e.Path = path + "z" },
		"id":     func(e *RawEvent) { e.RequestID = id2 },
	} {
		e := raw
		f(&e)
		r := Classify([]RawEvent{e}, rcs)[0]
		if r.Class != Unclassified || strings.Contains(r.Reason, "/") {
			t.Errorf("%s: %+v", name, r)
		}
	}
}
