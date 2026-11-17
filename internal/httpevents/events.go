// Package httpevents joins authenticated Agent operation receipts with raw HTTP
// events. Request headers, address and user-agent never establish trust.
package httpevents

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/ishizakahiroshi/heartdesk/httpclassification"
)

type Row struct {
	Result httpclassification.Result
	IP     string
	UA     string
	Source string
}

// LoadError contains only a stable diagnostic, never paths or log content.
// Receipt errors are nonfatal: raw rows remain threats. Raw read failures are
// fatal so the caller cannot publish a partially-read security score.
type LoadError struct {
	Code  string
	Fatal bool
	cause error
}

func (e *LoadError) Error() string { return e.Code }
func (e *LoadError) Unwrap() error { return e.cause }
func IsFatal(err error) bool       { var e *LoadError; return errors.As(err, &e) && e.Fatal }

type rawEvent struct {
	httpclassification.Event
	AgentID string `json:"agent_id"`
	IP      string `json:"ip"`
	UA      string `json:"ua"`
}
type receiptEvent struct {
	httpclassification.Receipt
	AgentID string `json:"agent_id"`
	Source  string `json:"source"`
}

func timestamp(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("invalid_timestamp")
}

func scan(ctx context.Context, path string, visit func([]byte)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 512*1024)
	for s.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		visit(s.Bytes())
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Err()
}

func Load(ctx context.Context, webPath string, now, cutoff time.Time) ([]Row, error) {
	scope := filepath.Base(filepath.Dir(webPath))
	raws := []rawEvent{}
	// Count even ID-bearing noncandidate responses so a replay in an otherwise
	// irrelevant 3xx/5xx response cannot authorize a second request.
	nonceCounts := map[string]int{}
	err := scan(ctx, webPath, func(line []byte) {
		var r rawEvent
		if json.Unmarshal(line, &r) != nil {
			return
		}
		ts, err := timestamp(r.TS)
		if err != nil || ts.Before(cutoff) || ts.After(now.Add(5*time.Minute)) {
			return
		}
		if r.AgentID != scope {
			r.RequestID = ""
		}
		if r.RequestID != "" {
			nonceCounts[r.RequestID]++
		}
		if !(r.Status >= 400 && r.Status < 500) && !(r.Status >= 200 && r.Status < 300 && r.RequestID != "") {
			return
		}
		raws = append(raws, r)
	})
	if err != nil {
		return nil, &LoadError{Code: "http_raw_read_failed", Fatal: true, cause: err}
	}
	receipts := []httpclassification.Receipt{}
	var diagnostic error
	err = scan(ctx, filepath.Join(filepath.Dir(webPath), "http_outcome.jsonl"), func(line []byte) {
		var r receiptEvent
		if json.Unmarshal(line, &r) != nil {
			diagnostic = &LoadError{Code: "http_receipt_malformed"}
			return
		}
		if r.AgentID != scope || r.Source != "http_outcome" {
			diagnostic = &LoadError{Code: "http_receipt_scope_mismatch"}
			return
		}
		ts, err := timestamp(r.TS)
		if err != nil || ts.Before(cutoff) || ts.After(now.Add(5*time.Minute)) {
			return
		}
		receipts = append(receipts, r.Receipt)
	})
	if err != nil {
		code := "http_receipt_read_failed"
		if os.IsNotExist(err) {
			code = "http_receipt_missing"
		}
		diagnostic = &LoadError{Code: code}
		if ctx.Err() != nil {
			return nil, &LoadError{Code: "http_read_cancelled", Fatal: true, cause: ctx.Err()}
		}
	}
	// A damaged receipt stream cannot authorize even its valid prefix.
	if diagnostic != nil {
		receipts = nil
	}
	events := make([]httpclassification.Event, len(raws))
	for i := range raws {
		if nonceCounts[raws[i].RequestID] > 1 {
			raws[i].RequestID = ""
		}
		events[i] = raws[i].Event
	}
	results := httpclassification.Classify(events, receipts, now, cutoff)
	rows := make([]Row, len(results))
	for i, r := range results {
		rows[i] = Row{Result: r, IP: raws[i].IP, UA: raws[i].UA, Source: scope}
	}
	return rows, diagnostic
}
