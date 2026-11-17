package httpevents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/httpclassification"
)

func fixture(t *testing.T) (string, time.Time, map[string]any, map[string]any) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "host-1")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	path := "/nextcloud/remote.php/dav/files/service/file.txt"
	sum := sha256.Sum256([]byte(path))
	raw := map[string]any{"ts": now.Add(-time.Minute).Format(time.RFC3339), "agent_id": "host-1", "request_id": strings.Repeat("a", 32), "ip": "203.0.113.10", "ua": "test-client", "method": "GET", "path": path, "status": 404}
	receipt := map[string]any{"ts": raw["ts"], "agent_id": "host-1", "source": "http_outcome", "request_id": raw["request_id"], "method": "GET", "path_hash": hex.EncodeToString(sum[:]), "status": 404, "operation": "fetch_file", "outcome": "error"}
	return filepath.Join(dir, "web_access.jsonl"), now, raw, receipt
}
func writeRows(t *testing.T, path string, rows ...map[string]any) {
	t.Helper()
	var b []byte
	for _, r := range rows {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, line...)
		b = append(b, '\n')
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadLateReceiptReclassifiesWithoutTrustingHeaders(t *testing.T) {
	path, now, raw, receipt := fixture(t)
	writeRows(t, path, raw)
	rows, err := Load(context.Background(), path, now, now.Add(-24*time.Hour))
	if len(rows) != 1 || rows[0].Result.Kind != "threat" || err == nil || IsFatal(err) {
		t.Fatal(rows, err)
	}
	writeRows(t, filepath.Join(filepath.Dir(path), "http_outcome.jsonl"), receipt)
	rows, err = Load(context.Background(), path, now, now.Add(-24*time.Hour))
	if err != nil || len(rows) != 1 || rows[0].Result.Kind != "integration_error" || rows[0].IP != "203.0.113.10" || rows[0].UA != "test-client" {
		t.Fatal(rows, err)
	}
}

func TestLoadScopeAndMalformedReceiptFailClosed(t *testing.T) {
	for _, kind := range []string{"receipt-scope", "receipt-source", "raw-scope", "old-raw", "malformed", "duplicate-raw", "nonce-replayed-in-500"} {
		t.Run(kind, func(t *testing.T) {
			path, now, raw, receipt := fixture(t)
			raws := []map[string]any{raw}
			switch kind {
			case "receipt-scope":
				receipt["agent_id"] = "other"
			case "receipt-source":
				receipt["source"] = "nginx"
			case "raw-scope":
				raw["agent_id"] = "other"
			case "old-raw":
				delete(raw, "agent_id")
				delete(raw, "request_id")
			case "duplicate-raw":
				raws = append(raws, raw)
			case "nonce-replayed-in-500":
				other := map[string]any{}
				for k, v := range raw {
					other[k] = v
				}
				other["status"] = 500
				raws = append(raws, other)
			}
			writeRows(t, path, raws...)
			receiptPath := filepath.Join(filepath.Dir(path), "http_outcome.jsonl")
			writeRows(t, receiptPath, receipt)
			if kind == "malformed" {
				f, _ := os.OpenFile(receiptPath, os.O_APPEND|os.O_WRONLY, 0600)
				f.WriteString("{\n")
				f.Close()
			}
			rows, _ := Load(context.Background(), path, now, now.Add(-24*time.Hour))
			if len(rows) == 0 {
				t.Fatal("raw failure disappeared")
			}
			for _, r := range rows {
				if r.Result.Kind != "threat" {
					t.Fatal("untrusted receipt suppressed raw failure", r)
				}
			}
		})
	}
}

func TestLoadStreamsTimeBoundsAndHonorsCancellation(t *testing.T) {
	path, now, raw, receipt := fixture(t)
	old := map[string]any{}
	for k, v := range raw {
		old[k] = v
	}
	old["ts"] = now.Add(-25 * time.Hour).Format(time.RFC3339)
	writeRows(t, path, old, raw)
	writeRows(t, filepath.Join(filepath.Dir(path), "http_outcome.jsonl"), receipt)
	rows, err := Load(context.Background(), path, now, now.Add(-24*time.Hour))
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rows, err := Load(ctx, path, now, now.Add(-24*time.Hour)); len(rows) != 0 || !IsFatal(err) {
		t.Fatal(rows, err)
	}
}

func TestSnapshotExactEventsSourceScopeAndSuccessClosure(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	makeRow := func(source, nonce, kind string, ts time.Time) Row {
		return Row{Source: source, Result: httpclassification.Result{Kind: kind, Operation: "fetch_file", ResourceHash: strings.Repeat("c", 64), Event: httpclassification.Event{TS: ts.Format(time.RFC3339), RequestID: nonce, Status: 404}}}
	}
	rows := []Row{makeRow("host-1", "old", "integration_error", now.Add(-3*time.Minute)), makeRow("host-1", "success", "success", now.Add(-2*time.Minute)), makeRow("host-1", "new", "integration_error", now.Add(-time.Minute)), makeRow("host-2", "new", "integration_error", now.Add(-time.Minute))}
	s := Snapshot(rows, now)
	if len(s.Resources) != 2 {
		t.Fatal(s)
	}
	for _, r := range s.Resources {
		if r.Count != 1 || len(r.Events) != 1 || len(r.Key) != 64 || len(r.Events[0].ID) != 64 {
			t.Fatal(r)
		}
	}
	if s.Resources[0].Key == s.Resources[1].Key || s.Resources[0].Events[0].ID == s.Resources[1].Events[0].ID {
		t.Fatal("source scopes collapsed")
	}
	path := filepath.Join(t.TempDir(), "snap.json")
	if err := WriteSnapshot(path, s); err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshot(path, s); err != nil {
		t.Fatal("atomic replacement", err)
	}
	var saved IntegrationSnapshot
	b, _ := os.ReadFile(path)
	if json.Unmarshal(b, &saved) != nil || len(saved.Resources) != 2 {
		t.Fatal("snapshot corrupted")
	}
}
