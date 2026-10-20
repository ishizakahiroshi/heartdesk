package monitor

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

// TailJSONL はJSONLファイルの末尾maxLines行をデコードして返す汎用ヘルパー。
// 解析に失敗した行はスキップする。
func TailJSONL[T any](path string, maxLines int) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if maxLines <= 0 {
		return []T{}, nil
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 512*1024), 512*1024)

	// 末尾 maxLines 行のみリングバッファに保持し、全行のメモリ展開を避ける
	// （fail2ban の 50000 行などで OOM しないように）。
	ring := make([][]byte, maxLines)
	count := 0
	for sc.Scan() {
		b := sc.Bytes()
		cp := make([]byte, len(b))
		copy(cp, b)
		ring[count%maxLines] = cp
		count++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	n := count
	start := 0
	if count > maxLines {
		n = maxLines
		start = count % maxLines // 保持している最古エントリの位置
	}

	out := make([]T, 0, n)
	for i := 0; i < n; i++ {
		var v T
		if json.Unmarshal(ring[(start+i)%maxLines], &v) == nil {
			out = append(out, v)
		}
	}
	return out, nil
}

// ScanJSONL は全行をストリーム処理するヘルパー（大ファイル向け）。
// fn が false を返すと走査を中止する。
func ScanJSONL[T any](path string, fn func(T) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 512*1024), 512*1024)
	for sc.Scan() {
		var v T
		if json.Unmarshal(sc.Bytes(), &v) == nil {
			if !fn(v) {
				break
			}
		}
	}
	return sc.Err()
}

func normalizeAgentID(agentID []string) string {
	if len(agentID) == 0 {
		return ""
	}
	return strings.TrimSpace(agentID[0])
}

func eventJSONLPath(localPath, agentID, kind string) string {
	if strings.TrimSpace(agentID) == "" {
		return heartdesk.Path(localPath)
	}
	return heartdesk.Path(filepath.Join("data/logs/agents", agentID, kind+".jsonl"))
}

// =============================================================================
// Agent JSONL イベント型（Agent が書き込む logs/*.jsonl のスキーマと一致させる）
// =============================================================================

// SSHLogEvent は logs/ssh.jsonl の1レコード
type SSHLogEvent struct {
	TS     string `json:"ts"`
	Event  string `json:"event"` // "accepted" / "failed" / "invalid_user" / "disconnect"
	User   string `json:"user"`
	IP     string `json:"ip"`
	Port   string `json:"port"`
	Method string `json:"method"` // "publickey" / "password" / ""
}

// F2BEvent は logs/fail2ban.jsonl の1レコード
type F2BEvent struct {
	TS       string `json:"ts"`
	Event    string `json:"event"` // "ban" / "unban" / "restore" / "found"
	Jail     string `json:"jail"`
	IP       string `json:"ip"`
	Failures int    `json:"failures,omitempty"`
}

// sshJSONLPath は data/logs/ssh.jsonl のフルパスを返す
func sshJSONLPath(agentID ...string) string {
	id := normalizeAgentID(agentID)
	return eventJSONLPath("data/logs/ssh.jsonl", id, "ssh")
}

// f2bJSONLPath は data/logs/fail2ban.jsonl のフルパスを返す
func f2bJSONLPath(agentID ...string) string {
	id := normalizeAgentID(agentID)
	return eventJSONLPath("data/logs/fail2ban.jsonl", id, "fail2ban")
}

// NginxLogEvent は logs/nginx.jsonl の1レコード
type NginxLogEvent struct {
	TS      string `json:"ts"`
	IP      string `json:"ip"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
	Bytes   int    `json:"bytes"`
	UA      string `json:"ua"`
	Referer string `json:"referer"`
	RespMs  int    `json:"resp_ms"`
}

// nginxJSONLPath は data/logs/nginx.jsonl のフルパスを返す
func webAccessJSONLPath(agentID ...string) string {
	id := normalizeAgentID(agentID)
	return eventJSONLPath("data/logs/nginx.jsonl", id, "web_access")
}

// NCEvent は logs/nextcloud.jsonl の1レコード（Agent が正規化して書き込む）
type NCEvent struct {
	TS     string `json:"ts"`
	Source string `json:"source"` // "app"（nextcloud.log）/ "audit"（audit.log）
	Level  string `json:"level"`  // "debug" / "info" / "warning" / "error"
	User   string `json:"user"`
	IP     string `json:"ip"`
	Msg    string `json:"msg"`
	App    string `json:"app"`
	// Agent 生成 JSONL では使わないが nc_login / audit_anomaly で必要な追加フィールド
	ReqID     string `json:"req_id,omitempty"`
	URL       string `json:"url,omitempty"`
	Method    string `json:"method,omitempty"`
	UserAgent string `json:"ua,omitempty"`
	Exception *struct {
		Message string `json:"message"`
	} `json:"exception,omitempty"`
}

// ncJSONLPath は data/logs/nextcloud.jsonl のフルパスを返す
func ncJSONLPath(agentID ...string) string {
	id := normalizeAgentID(agentID)
	return eventJSONLPath("data/logs/nextcloud.jsonl", id, "nextcloud_login")
}

func ncAuditJSONLPath(agentID ...string) string {
	id := normalizeAgentID(agentID)
	return eventJSONLPath("data/logs/nextcloud.jsonl", id, "audit")
}

func honeypotJSONLPath(agentID string) string {
	return eventJSONLPath("", agentID, "honeypot")
}
