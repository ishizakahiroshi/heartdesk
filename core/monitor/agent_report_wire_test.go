package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartpost/agentsig"
	"github.com/ishizakahiroshi/heartpost/report"
)

// このファイルは heartpost（収集と送信の正本）と heartdesk（受信側）のワイヤ仕様が
// 食い違っていないことを固定する。testdata/report_v1.json は heartpost の
// report/testdata/report_v1.json をそのまま持ち込んだもの。
//
// 落ちたときは「テストを直す」前に、**稼働中の agent が受信側から拒否されないか**を
// 先に考える。すでに動いている agent は勝手には更新されないので、キー名の変更・
// 削除・型変更は「全台を入れ替えるまで受信できない期間ができる」ことと同義になる。
//
// heartpost 側の対応するテスト: report/report_golden_test.go

// TestWireGoldenDecodesIntoReceiveTypes は heartpost が送る payload が、
// 受信側の型へ欠けなく入ることを確認する。
func TestWireGoldenDecodesIntoReceiveTypes(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash("testdata/report_v1.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	// 受信ハンドラが最初に入れる型。
	var got AgentReport
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("受信側の AgentReport へデコードできない: %v", err)
	}

	if got.AgentID != "demo-web-01" {
		t.Fatalf("agent_id = %q", got.AgentID)
	}
	if got.AgentLabel != "demo web server" {
		t.Fatalf("agent_label = %q", got.AgentLabel)
	}
	if got.AgentType != "rental" {
		t.Fatalf("agent_type = %q", got.AgentType)
	}
	if got.ReportedAt != "2026-01-02T03:04:05Z" {
		t.Fatalf("reported_at = %q", got.ReportedAt)
	}
	if len(got.Collectors) != 6 {
		t.Fatalf("collectors = %d 件, want 6", len(got.Collectors))
	}

	// 保存用の型でも同じ形が保たれること。
	var rec agentReportRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("agentReportRecord へデコードできない: %v", err)
	}
	if rec.AgentID != got.AgentID || rec.ReportedAt != got.ReportedAt {
		t.Fatalf("record = %+v", rec)
	}
}

// TestWireCollectorErrorIsDistinguishable は「対象外で nil」と「取得に失敗」を
// 受信側が区別できることを確認する。区別できないと、欠測を正常と読み違える。
func TestWireCollectorErrorIsDistinguishable(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash("testdata/report_v1.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var got AgentReport
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// network は取得対象外なので null。
	if string(got.Collectors["network"]) != "null" {
		t.Fatalf("network = %s, want null", got.Collectors["network"])
	}

	// memory は収集に失敗したので _error を持つオブジェクト。
	var memErr map[string]string
	if err := json.Unmarshal(got.Collectors["memory"], &memErr); err != nil {
		t.Fatalf("memory: %v", err)
	}
	if memErr[report.ErrorKey] == "" {
		t.Fatalf("memory に %s が入っていない: %v", report.ErrorKey, memErr)
	}
}

// TestWireSignatureVerifies は heartpost 側で計算した署名を、受信側の検証が
// そのまま受け入れることを確認する。署名の実装が 1 つであることの確認でもある。
func TestWireSignatureVerifies(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash("testdata/report_v1.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	const key = "0123456789abcdef"
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	sig := agentsig.Compute(key, ts, raw)
	if !agentsig.Verify(key, ts, raw, sig) {
		t.Fatal("自分で作った署名を検証できない")
	}
	if agentsig.Verify(key, ts, append(raw, ' '), sig) {
		t.Fatal("本文を書き換えても検証が通ってしまう")
	}
	if agentsig.Verify("other-key", ts, raw, sig) {
		t.Fatal("鍵が違っても検証が通ってしまう")
	}
}

// TestWireHeaderNamesMatchReceiver は受信側が読むヘッダ名が、送信側の定数と
// 一致していることを固定する。片方だけ変えると全 agent が 401 になる。
func TestWireHeaderNamesMatchReceiver(t *testing.T) {
	cases := map[string]string{
		report.HeaderAgentID:   "X-Agent-Id",
		report.HeaderTimestamp: "X-Agent-Timestamp",
		report.HeaderSignature: "X-Agent-Signature",
		report.DefaultPath:     "/api/agent/report",
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("定数 = %q, want %q", got, want)
		}
	}
}
