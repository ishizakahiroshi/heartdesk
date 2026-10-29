package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInventoryJSONLHistoryNewestFirstAndBounded(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "report_alpha-vps-one_202601.jsonl")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	// The ancient malformed data must not be read beyond the bounded window.
	if _, err = f.WriteString("invalid\n" + strings.Repeat(" ", 17<<20) + "\n"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"old", "new"} {
		row := map[string]any{"agent_id": "alpha-vps-one", "collectors": map[string]any{"inventory": map[string]string{"value": value}}}
		if err = json.NewEncoder(f).Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	rows, limited, err := inventoryJSONLHistory(dir, "alpha-vps-one")
	if err != nil || !limited || len(rows) != 2 || !strings.Contains(string(rows[0]), "new") || !strings.Contains(string(rows[1]), "old") {
		t.Fatalf("rows=%s limited=%v error=%v", rows, limited, err)
	}
}

func TestInventoryJSONLHistorySkipsUnfinishedNewestTail(t *testing.T) {
	for _, tail := range []string{
		`{"agent_id":"alpha-vps-one","collectors":{"inventory":`,
		`{"agent_id":"alpha-vps-one","collectors":{"inventory":{"value":"unfinished"}}}`,
	} {
		t.Run(tail, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "report_alpha-vps-one_202601.jsonl")
			complete := `{"agent_id":"alpha-vps-one","collectors":{"inventory":{"value":"complete"}}}` + "\n"
			body := complete + tail
			if err := os.WriteFile(file, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			rows, limited, err := inventoryJSONLHistory(dir, "alpha-vps-one")
			if err != nil || !limited || len(rows) != 1 || !strings.Contains(string(rows[0]), "complete") {
				t.Fatalf("rows=%s limited=%v err=%v", rows, limited, err)
			}
			unchanged, err := os.ReadFile(file)
			if err != nil || string(unchanged) != body {
				t.Fatal("history reader changed source")
			}
		})
	}
}

func TestInventoryJSONLHistoryRejectsCompleteCorruptRows(t *testing.T) {
	for _, body := range []string{
		"invalid\n",
		`{"agent_id":"alpha-vps-one","collectors":{"inventory":` + "\n",
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "report_alpha-vps-one_202601.jsonl"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := inventoryJSONLHistory(dir, "alpha-vps-one"); err == nil {
			t.Fatal("complete corrupt row was hidden")
		}
	}
}

func TestInventoryJSONLHistoryRejectsUnterminatedOlderFile(t *testing.T) {
	dir := t.TempDir()
	old := `{"agent_id":"alpha-vps-one","collectors":{"inventory":{"value":"old"}}}`
	if err := os.WriteFile(filepath.Join(dir, "report_alpha-vps-one_202601.jsonl"), []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report_alpha-vps-one_202602.jsonl"), []byte("\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inventoryJSONLHistory(dir, "alpha-vps-one"); err == nil {
		t.Fatal("unterminated older row was accepted")
	}
}
