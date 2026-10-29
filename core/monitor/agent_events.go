package monitor

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

const agentEventMaxPerCollector = 1000

// agentEventDedupeWindow は重複確認に使うキーを持つ期間。
// Agent は新しいイベントだけを送るため、同じイベントが再び届くのは送り直しと、
// Agent 側の記録が消えてログ末尾を送り直したときだけで、どちらも 1 日以内に収まる。
const agentEventDedupeWindow = 48 * time.Hour

// agentEventSeedChunk は起動後の初回に、イベント JSONL を末尾から読むときの 1 回の読み込み量。
const agentEventSeedChunk = 1 << 20

// agentEventSeedStopAfterOld は、末尾から読んでいて ts が窓より前の行だけの塊がこの量だけ続いたら止める量。
// 長く止まっていた Agent が古いイベントをまとめて送ると、ファイル末尾に古い行が並び、その手前に
// 直近の行が残るため、古い塊 1 つでは止めない（1 報告は 1 種類あたり最大 1000 件で、数百 KB に収まる）。
var agentEventSeedStopAfterOld int64 = 8 << 20

// agentEventSeedMaxBytes は初回に読む量の上限。ts が読めない行ばかりのファイルや、
// 窓の中の行が極端に多いファイルでも、全体を読んでメモリに載せることはしない
// （1 日に約 5 万行のホストで、直近 48 時間分は約 80MB）。
var agentEventSeedMaxBytes int64 = 128 << 20

// agentEventNow はテストで時刻を差し替えるための関数。
var agentEventNow = time.Now

// agentEventDedupeIndex はイベント JSONL 1 本ぶんの重複確認キー（キー → イベント時刻）。
// 報告のたびにファイル全体を読み直すと、ファイルの大きさに比例して読み込み量とメモリが増え、
// 処理が Agent の待ち時間を超えて送り直しが重なる（2026-10 に 3.6GB で Monitor が OOM）。
// そのため初回だけ直近の分を読み、以後はプロセス内で持ち続ける。mu は同じファイルへの書き込みも直列にする。
type agentEventDedupeIndex struct {
	mu       sync.Mutex
	loaded   bool
	keys     map[string]time.Time
	prunedAt time.Time
}

// agentEventIndexes は path → *agentEventDedupeIndex。
var agentEventIndexes sync.Map

func agentEventIndexFor(path string) *agentEventDedupeIndex {
	v, _ := agentEventIndexes.LoadOrStore(path, &agentEventDedupeIndex{})
	return v.(*agentEventDedupeIndex)
}

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
	base := heartdesk.Path("data/logs/agents")
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
	case "http_outcome":
		// Receipts written by the integration (heartpost http_outcome collector;
		// httpclassification, policy v2). heartpost may re-send old receipts after
		// a rotation: the dedupe key covers every receipt field, so an identical
		// re-send is dropped while a conflicting one with the same request_id is kept
		// (and makes that request_id ambiguous, so it matches nothing).
		return "http_outcome", "http_outcome"
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
	// Events that carry a request id (and receipts, which carry a path hash and
	// an operation) must not collapse into each other when everything else is
	// equal. Appended only when present so existing keys do not change.
	for _, k := range []string{"request_id", "path_hash", "operation", "outcome"} {
		if v := eventString(ev, k); v != "" {
			parts = append(parts, k+"="+v)
		}
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
	idx := agentEventIndexFor(path)
	idx.mu.Lock()
	defer idx.mu.Unlock()

	now := agentEventNow()
	cutoff := now.Add(-agentEventDedupeWindow)
	if idx.loaded {
		// ファイルが外から消された・別名へ移されたときは、表を作り直す（消えた行のキーで弾かない）
		if _, err := os.Stat(path); os.IsNotExist(err) {
			idx.loaded = false
		}
	}
	if !idx.loaded {
		idx.keys = loadAgentEventDedupeKeys(path, cutoff)
		idx.loaded = true
		idx.prunedAt = now
	}

	// イベント JSONL は heartdesk プロセス専用のため 0600。
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open agent events: %w", err)
	}
	defer f.Close()

	// 途中で書き込みに失敗したら、どこまでファイルに入ったか分からないので、次の報告で表を作り直す。
	ok := false
	defer func() {
		if !ok {
			idx.loaded = false
		}
	}()

	written := make(map[string]time.Time, len(records))
	w := bufio.NewWriter(f)
	for _, rec := range records {
		key, _ := rec["dedupe_key"].(string)
		if key == "" {
			continue
		}
		if _, dup := idx.keys[key]; dup {
			continue
		}
		if _, dup := written[key]; dup {
			continue
		}
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
		// 窓より前の時刻のイベント（長く止まっていた Agent の古い分）は、受け取った時刻で持つ。
		// イベントの時刻のままだと次の掃除ですぐ消え、送り直しを弾けない。
		ts := agentEventTime(rec, now)
		if ts.Before(cutoff) {
			ts = now
		}
		written[key] = ts
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush agent events: %w", err)
	}
	for key, ts := range written {
		idx.keys[key] = ts
	}
	ok = true
	if now.Sub(idx.prunedAt) >= time.Hour {
		for key, ts := range idx.keys {
			if ts.Before(cutoff) {
				delete(idx.keys, key)
			}
		}
		idx.prunedAt = now
	}
	return nil
}

// agentEventTime はイベントの ts を時刻にする。読めないときは now（受け取った時刻）を使う。
func agentEventTime(rec agentEventRecord, now time.Time) time.Time {
	if s, _ := rec["ts"].(string); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t
		}
	}
	return now
}

// loadAgentEventDedupeKeys はイベント JSONL を末尾から読み、ts が cutoff 以降のイベントの重複確認キーを返す。
// ファイルは追記の順にほぼ時刻順なので、cutoff より前の行だけの塊が agentEventSeedStopAfterOld 続いたら止める。
// どの場合も agentEventSeedMaxBytes より先は読まない（ファイル全体は読まない）。
// ts が読めない行のキーは残すが、止めるかどうかの判断には使わない。
func loadAgentEventDedupeKeys(path string, cutoff time.Time) map[string]time.Time {
	keys := make(map[string]time.Time)
	f, err := os.Open(path)
	if err != nil {
		return keys
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return keys
	}
	offset := fi.Size()
	var carry []byte // 1 つ後ろの読み込み分の先頭にあった、行の途中
	var readTotal, oldRun int64
	for offset > 0 {
		if readTotal >= agentEventSeedMaxBytes {
			log.Printf("WARN: agent_events: stopped reading %s for dedupe keys after %d bytes", path, readTotal)
			break
		}
		readSize := int64(agentEventSeedChunk)
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize
		readTotal += readSize
		buf := make([]byte, readSize, readSize+int64(len(carry)))
		if _, err := f.ReadAt(buf, offset); err != nil && err != io.EOF {
			log.Printf("WARN: agent_events: read %s for dedupe keys: %v", path, err)
			break
		}
		buf = append(buf, carry...)
		lines := bytes.Split(buf, []byte{'\n'})
		carry = nil
		if offset > 0 {
			// 先頭の 1 行は前の読み込み分とつながっている可能性があるので次へ持ち越す
			carry = append([]byte(nil), lines[0]...)
			lines = lines[1:]
		}

		datedLines, recentLines := 0, 0
		for _, line := range lines {
			key, ts, dated, ok := parseAgentEventKey(line)
			if !ok {
				continue
			}
			if !dated {
				keys[key] = agentEventNow()
				continue
			}
			datedLines++
			if ts.Before(cutoff) {
				continue
			}
			recentLines++
			keys[key] = ts
		}
		if datedLines > 0 && recentLines == 0 {
			oldRun += readSize
			if oldRun >= agentEventSeedStopAfterOld {
				break
			}
		} else if recentLines > 0 {
			oldRun = 0
		}
	}
	return keys
}

// parseAgentEventKey は JSONL の 1 行から dedupe_key と ts を取り出す。
func parseAgentEventKey(line []byte) (key string, ts time.Time, dated bool, ok bool) {
	if len(bytes.TrimSpace(line)) == 0 {
		return "", time.Time{}, false, false
	}
	var rec struct {
		DedupeKey string `json:"dedupe_key"`
		TS        string `json:"ts"`
	}
	if err := json.Unmarshal(line, &rec); err != nil || rec.DedupeKey == "" {
		return "", time.Time{}, false, false
	}
	t, err := time.Parse(time.RFC3339, rec.TS)
	if err != nil {
		return rec.DedupeKey, time.Time{}, false, true
	}
	return rec.DedupeKey, t, true, true
}
