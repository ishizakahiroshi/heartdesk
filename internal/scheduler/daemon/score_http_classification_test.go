package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/httpclassification"
)

const (
	hcIP   = "203.0.113.20"
	hcID1  = "00000000000000000000000000000001"
	hcID2  = "00000000000000000000000000000002"
	hcPath = "/nextcloud/remote.php/dav/files/alice/folder/"
)

func hcRaw(agent, id, method string, status int, ts string) string {
	return fmt.Sprintf(`{"ts":%q,"ip":%q,"agent_id":%q,"request_id":%q,"method":%q,"path":%q,"status":%d}`+"\n",
		ts, hcIP, agent, id, method, hcPath+"?q=1", status)
}

func hcReceipt(agent, id, method string, status int, op, outcome, ts, pathHash string) string {
	return fmt.Sprintf(`{"ts":%q,"agent_id":%q,"request_id":%q,"method":%q,"path_hash":%q,"status":%d,"operation":%q,"outcome":%q}`+"\n",
		ts, agent, id, method, pathHash, status, op, outcome)
}

func hcRun(t *testing.T, raw, receipts string) nc4xxClassified {
	t.Helper()
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "web_access.jsonl")
	if err := os.WriteFile(rawPath, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if receipts != "" {
		if err := os.WriteFile(filepath.Join(dir, "integration_receipt.jsonl"), []byte(receipts), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cutoff := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	return collectNC4xxEventClassified(context.Background(), rawPath, filepath.Join(dir, "integration_receipt.jsonl"), cutoff, func(string, string) {})
}

func TestNC4xxExpectedReceiptIsNotScored(t *testing.T) {
	h := httpclassification.PathHash(hcPath)
	got := hcRun(t,
		hcRaw("agent-a", hcID1, "MKCOL", 405, "2026-10-30T10:00:00Z"),
		hcReceipt("agent-a", hcID1, "MKCOL", 405, "ensure_collection", "expected", "2026-10-30T10:00:01Z", h))
	if got.Scored[hcIP] != 0 || got.Expected[hcIP] != 1 || got.IntegrationErr[hcIP] != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestNC4xxIntegrationErrorIsNotScoredButCounted(t *testing.T) {
	h := httpclassification.PathHash(hcPath)
	got := hcRun(t,
		hcRaw("agent-a", hcID1, "GET", 404, "2026-10-30T10:00:00Z"),
		hcReceipt("agent-a", hcID1, "GET", 404, "fetch_file", "integration_error", "2026-10-30T10:00:00Z", h))
	if got.Scored[hcIP] != 0 || got.IntegrationErr[hcIP] != 1 {
		t.Fatalf("%+v", got)
	}
}

// Positive controls: the same method/status without a trusted matching receipt
// keeps scoring.
func TestNC4xxStillScoredWithoutTrustedReceipt(t *testing.T) {
	h := httpclassification.PathHash(hcPath)
	okRaw := hcRaw("agent-a", hcID1, "MKCOL", 405, "2026-10-30T10:00:00Z")
	okRc := hcReceipt("agent-a", hcID1, "MKCOL", 405, "ensure_collection", "expected", "2026-10-30T10:00:01Z", h)
	cases := map[string]struct{ raw, rc string }{
		"no receipt": {okRaw, ""},
		"no request id": {
			hcRaw("agent-a", "", "MKCOL", 405, "2026-10-30T10:00:00Z"), okRc},
		"receipt from another agent": {
			okRaw, hcReceipt("agent-b", hcID1, "MKCOL", 405, "ensure_collection", "expected", "2026-10-30T10:00:01Z", h)},
		"spoofed path hash": {
			okRaw, hcReceipt("agent-a", hcID1, "MKCOL", 405, "ensure_collection", "expected", "2026-10-30T10:00:01Z", httpclassification.PathHash("/other"))},
		"spoofed status": {
			okRaw, hcReceipt("agent-a", hcID1, "MKCOL", 404, "ensure_collection", "expected", "2026-10-30T10:00:01Z", h)},
		"duplicate receipt": {okRaw, okRc + okRc},
		"duplicate raw":     {okRaw + okRaw, okRc},
		"late receipt": {
			okRaw, hcReceipt("agent-a", hcID1, "MKCOL", 405, "ensure_collection", "expected", "2026-10-30T10:06:00Z", h)},
		"other request id": {
			okRaw, hcReceipt("agent-a", hcID2, "MKCOL", 405, "ensure_collection", "expected", "2026-10-30T10:00:01Z", h)},
		"403 is never excluded": {
			hcRaw("agent-a", hcID1, "MKCOL", 403, "2026-10-30T10:00:00Z"),
			hcReceipt("agent-a", hcID1, "MKCOL", 403, "ensure_collection", "expected", "2026-10-30T10:00:01Z", h)},
		"unknown operation": {
			okRaw, hcReceipt("agent-a", hcID1, "MKCOL", 405, "mystery", "expected", "2026-10-30T10:00:01Z", h)},
		"malformed receipt line": {okRaw, "{not json\n"},
	}
	for name, c := range cases {
		got := hcRun(t, c.raw, c.rc)
		want := strings.Count(c.raw, "\n")
		if got.Scored[hcIP] != want || got.Expected[hcIP] != 0 || got.IntegrationErr[hcIP] != 0 {
			t.Errorf("%s: want scored=%d, got %+v", name, want, got)
		}
	}
}

// The receipt may arrive after the raw event: each run recomputes.
func TestNC4xxLateReceiptRecomputed(t *testing.T) {
	h := httpclassification.PathHash(hcPath)
	raw := hcRaw("agent-a", hcID1, "PROPFIND", 404, "2026-10-30T10:00:00Z")
	if got := hcRun(t, raw, ""); got.Scored[hcIP] != 1 {
		t.Fatalf("before receipt: %+v", got)
	}
	rc := hcReceipt("agent-a", hcID1, "PROPFIND", 404, "path_exists", "expected", "2026-10-30T10:00:02Z", h)
	if got := hcRun(t, raw, rc); got.Scored[hcIP] != 0 || got.Expected[hcIP] != 1 {
		t.Fatalf("after receipt: %+v", got)
	}
}

func TestWriteHTTPClassifiedCSV(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x", "threat_score_http_classified.csv")
	if err := writeHTTPClassifiedCSV(p, "2026-10-30T10:00:00", map[string]int{hcIP: 3}, map[string]int{"203.0.113.21": 1}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	for _, w := range []string{"nc_4xx_expected", hcIP + ",3,0", "203.0.113.21,0,1"} {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in %q", w, s)
		}
	}
}
