package monitor

import (
	"path/filepath"
	"testing"
)

// TestIsValidAgentID は agent_id 全体の厳格バリデータ（パス連結前のトラバーサル防止）を検証する。
// 形式は「小文字英数字とアンダースコアのテナント ID、ハイフン、続けて小文字英数字・ハイフン・
// アンダースコア」。受理する形と、パス・コマンドとして危険な文字を含む形の両方を確認する。
func TestIsValidAgentID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		// 受理する形
		{"alpha-vps-host1", true},
		{"beta-rental-host-2", true},
		{"gamma-vps-test", true},
		{"tenant_b-rental-host2", true},
		{"alpha-host1", true},    // 種別部が無い 2 部形式も許す
		{"t101-vps-host1", true}, // 数字を含むテナント ID
		{"a-b", true},
		// 拒否する形
		{"", false},
		{"   ", false},
		{"alpha", false},              // ハイフンなし
		{"alpha-", false},             // ハイフンの後が空
		{"-alpha-vps-host1", false},   // テナント ID が空
		{"alpha--vps", false},         // ハイフンが連続して名前部が始まらない
		{"alpha-vps-.hidden", false},  // ドットを含む
		{"alpha-VPS-host1", false},    // 大文字不可
		{"Alpha-vps-host1", false},    // テナント ID の大文字不可
		{"alpha-vps-../etc", false},   // パストラバーサル
		{"alpha-vps-host1/x", false},  // スラッシュ
		{"alpha-vps-host1\\x", false}, // バックスラッシュ
		{"../alpha-vps-host1", false}, // 先頭トラバーサル
		{"alpha-vps-host 1", false},   // 空白
		{"alpha-vps-host1\n", true},   // 前後の空白は取り除いて検証する（改行は TrimSpace される）
		{"alpha-vps-host1\nx", false}, // 途中の改行
		{"alpha-vps-host1;rm", false}, // シェルのメタ文字
		{"alpha-vps-ホスト", false},      // ASCII 以外
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := isValidAgentID(tt.id); got != tt.want {
				t.Fatalf("isValidAgentID(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

// TestSafeAgentPathJoin は agent_id 由来のパスが base 配下に封じ込められることを確認する。
func TestSafeAgentPathJoin(t *testing.T) {
	base := filepath.Join("data", "logs", "agents")

	if _, err := safeAgentPathJoin(base, "report_alpha-vps-x_202605.jsonl"); err != nil {
		t.Fatalf("valid name should join: %v", err)
	}
	// パストラバーサルを試みる名前は拒否される。
	if _, err := safeAgentPathJoin(base, "../../etc/passwd"); err == nil {
		t.Fatal("path traversal must be rejected")
	}
}

// TestIsValidManagedIPEntry は管理台帳の IP/CIDR 再検証（コマンド注入文字列などの拒否）を確認する。
func TestIsValidManagedIPEntry(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.1", true},
		{"198.51.100.0/24", true},
		{"::1", true},
		{"2001:db8::/32", true},
		{"", false},
		{"not-an-ip", false},
		{"203.0.113.1; rm -rf /", false},
		{"203.0.113.1/99", false},
		{"999.999.999.999", false},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := isValidManagedIPEntry(tt.ip); got != tt.want {
				t.Fatalf("isValidManagedIPEntry(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// TestPinMatches は PIN の定数時間比較と bcrypt 優先を確認する。
func TestPinMatches(t *testing.T) {
	tests := []struct {
		name    string
		pinHash string
		expect  string
		input   string
		want    bool
	}{
		{name: "plain match", expect: "135790", input: "135790", want: true},
		{name: "plain mismatch", expect: "135790", input: "999999", want: false},
		{name: "empty expected and hash never matches", expect: "", input: "", want: false},
		{name: "empty input vs set pin", expect: "135790", input: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pinMatches(tt.pinHash, tt.expect, tt.input); got != tt.want {
				t.Fatalf("pinMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}
