// Package httpclassload reads the agent event files that feed
// httpclassification: web_access.jsonl (raw nginx events) and
// integration_receipt.jsonl (receipts written by the integration).
package httpclassload

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/ishizakahiroshi/heartdesk/httpclassification"
)

const (
	// RawFile and ReceiptFile are the file names inside an agent event dir.
	RawFile     = "web_access.jsonl"
	ReceiptFile = "integration_receipt.jsonl"
)

// Event is one raw access event with the fields the callers need.
type Event struct {
	httpclassification.RawEvent
	IP string
}

type rawLine struct {
	TS        string `json:"ts"`
	IP        string `json:"ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	RequestID string `json:"request_id"`
	AgentID   string `json:"agent_id"`
}

type scopeLine struct {
	AgentID string `json:"agent_id"`
}

// Load reads the raw and receipt files (receipt file may be absent). Scope of every record is its own agent_id
// field (written by the ingest step from the authenticated report) and falls
// back to the raw file's directory name, so a record carrying another agent's id never
// matches this directory's records. keep filters raw events (nil keeps all
// with a parseable ts at or after cutoff). Unreadable files yield nothing.
func Load(rawPath, receiptPath string, cutoff time.Time, parseTime func(string) (time.Time, error), keep func(Event) bool) ([]Event, []httpclassification.Receipt) {
	fallback := filepath.Base(filepath.Dir(rawPath))
	var events []Event
	_ = readJSONL(rawPath, func(line []byte) {
		var l rawLine
		if json.Unmarshal(line, &l) != nil {
			return
		}
		t, err := parseTime(l.TS)
		if err != nil || t.Before(cutoff) {
			return
		}
		scope := l.AgentID
		if scope == "" {
			scope = fallback
		}
		e := Event{IP: l.IP, RawEvent: httpclassification.RawEvent{
			Scope: scope, RequestID: l.RequestID, Method: l.Method,
			Path: l.Path, Status: l.Status, Time: t,
		}}
		if keep == nil || keep(e) {
			events = append(events, e)
		}
	})
	var receipts []httpclassification.Receipt
	_ = readJSONL(receiptPath, func(line []byte) {
		var s scopeLine
		if json.Unmarshal(line, &s) != nil {
			return
		}
		scope := s.AgentID
		if scope == "" {
			scope = fallback
		}
		r, ok := httpclassification.ParseReceipt(line, scope, parseTime)
		if !ok {
			return
		}
		receipts = append(receipts, r)
	})
	return events, receipts
}

func readJSONL(path string, fn func([]byte)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		fn(append([]byte(nil), b...))
	}
	return sc.Err()
}

// Classify runs httpclassification over the loaded data.
func Classify(events []Event, receipts []httpclassification.Receipt) []httpclassification.Result {
	raw := make([]httpclassification.RawEvent, len(events))
	for i, e := range events {
		raw[i] = e.RawEvent
	}
	return httpclassification.Classify(raw, receipts)
}
