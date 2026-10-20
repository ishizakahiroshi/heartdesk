package monitor

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
)

const agentEventMaxPerCollector = 1000

type agentCollectorEvents struct {
	Events []map[string]interface{} `json:"events"`
}

type agentEventRecord map[string]interface{}

// agentEventDirPath は agent のイベントログ格納ディレクトリパスを返す。
//
// agent_id を厳格バリデータで検証し、合致しない場合は
// base 配下の "_invalid" サブディレクトリへ隔離する（パストラバーサルで base 外へ抜けることを防ぐ）。
// 正規経路では agent_id はハンドラ側で検証済みのため通常は到達しない。
func agentEventDirPath(agentID string) string {
	base := sab.SabPath("data/logs/agents")
	if !isValidAgentID(agentID) {
		log.Printf("WARN: agent_events: invalid agent_id for event dir, quarantining: %q", agentID)
		return filepath.Join(base, "_invalid")
	}
	return filepath.Join(base, agentID)
}

func saveAgentEventStreams(record agentReportRecord) error {
	for collectorName, raw := range record.Collectors {
		events, ok := decodeCollectorEvents(raw)
		if !ok || len(events) == 0 {
			continue
		}
		if len(events) > agentEventMaxPerCollector {
			events = events[len(events)-agentEventMaxPerCollector:]
		}

		byKind := make(map[string][]agentEventRecord)
		for _, ev := range events {
			normalized, kind, ok := normalizeAgentEvent(record, collectorName, ev)
			if !ok {
				continue
			}
			byKind[kind] = append(byKind[kind], normalized)
		}

		for kind, records := range byKind {
			if len(records) == 0 {
				continue
			}
			if err := appendAgentEvents(record.AgentID, kind, records); err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeCollectorEvents(raw json.RawMessage) ([]map[string]interface{}, bool) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, false
	}
	var result agentCollectorEvents
	if err := json.Unmarshal(raw, &result); err != nil || len(result.Events) == 0 {
		return nil, false
	}
	return result.Events, true
}

func normalizeAgentEvent(record agentReportRecord, collectorName string, ev map[string]interface{}) (agentEventRecord, string, bool) {
	kind, source := eventKindAndSource(collectorName, ev)
	if kind == "" {
		return nil, "", false
	}

	ts := eventString(ev, "ts")
	if ts == "" {
		return nil, "", false
	}

	out := make(agentEventRecord, len(ev)+5)
	for k, v := range ev {
		out[k] = v
	}
	out["agent_id"] = record.AgentID
	out["agent_type"] = record.AgentType
	out["source"] = source
	out["ts"] = ts

	dedupeKey := eventString(ev, "dedupe_key")
	if dedupeKey == "" {
		dedupeKey = buildAgentEventDedupeKey(source, ts, ev)
	}
	out["dedupe_key"] = dedupeKey
	return out, kind, true
}

func eventKindAndSource(collectorName string, ev map[string]interface{}) (string, string) {
	switch collectorName {
	case "ssh":
		return "ssh", "ssh"
	case "nginx":
		return "web_access", "nginx"
	case "apache_log":
		return "web_access", "apache"
	case "fail2ban":
		return "fail2ban", "fail2ban"
	case "honeypot":
		return "honeypot", "honeypot"
	case "nextcloud":
		if eventString(ev, "source") == "audit" {
			return "audit", "audit"
		}
		return "nextcloud_login", "nextcloud"
	default:
		return "", ""
	}
}

func buildAgentEventDedupeKey(source, ts string, ev map[string]interface{}) string {
	parts := []string{
		source,
		ts,
		eventString(ev, "ip"),
		eventString(ev, "method"),
		eventString(ev, "event"),
		eventString(ev, "path"),
		eventString(ev, "query"),
		eventString(ev, "trigger"),
		eventString(ev, "status"),
		eventString(ev, "user"),
		eventString(ev, "msg"),
		eventString(ev, "ua"),
		eventString(ev, "user_agent"),
	}
	joined := strings.Join(parts, "|")
	if len(joined) <= 240 {
		return joined
	}
	sum := sha256.Sum256([]byte(joined))
	return source + "|" + ts + "|" + hex.EncodeToString(sum[:])
}

func eventString(ev map[string]interface{}, key string) string {
	v, ok := ev[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

func appendAgentEvents(agentID, kind string, records []agentEventRecord) error {
	dir := agentEventDirPath(agentID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir agent events: %w", err)
	}

	path := filepath.Join(dir, kind+".jsonl")
	seen := loadAgentEventDedupeKeys(path)

	// イベント JSONL は sab プロセス専用のため 0600。
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open agent events: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, rec := range records {
		key, _ := rec["dedupe_key"].(string)
		if key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		b, err := json.Marshal(rec)
		if err != nil {
			continue
		}
		if _, err := w.Write(b); err != nil {
			return fmt.Errorf("write agent event: %w", err)
		}
		if err := w.WriteByte('\n'); err != nil {
			return fmt.Errorf("write agent event newline: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush agent events: %w", err)
	}
	return nil
}

func loadAgentEventDedupeKeys(path string) map[string]struct{} {
	seen := make(map[string]struct{})
	f, err := os.Open(path)
	if err != nil {
		return seen
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 512*1024), 512*1024)
	for sc.Scan() {
		var rec map[string]interface{}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		key, _ := rec["dedupe_key"].(string)
		if key != "" {
			seen[key] = struct{}{}
		}
	}
	return seen
}
