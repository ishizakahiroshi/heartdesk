package monitor

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newMultipartRequest は画面側の JS と同じ形（FormData を fetch の body に渡す）の
// POST を作る。content-type は multipart/form-data になる。
func newMultipartRequest(t *testing.T, values map[string]string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range values {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField(%s): %v", k, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/?api=save_alert_rules", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// TestParseActionForm_Multipart は multipart/form-data の値が r.Form に載ることを見る。
// これが落ちると通知設定カードの保存が「しきい値が不正です」で全滅する
// （multipart の値を ParseForm だけで受けると空になる問題の回帰検査）。
func TestParseActionForm_Multipart(t *testing.T) {
	req := newMultipartRequest(t, map[string]string{
		"action":                              "save_alert_rules",
		"alert_rules[memory_high][threshold]": "85",
		"alert_rules[memory_high][enabled]":   "1",
	})

	if err := parseActionForm(req); err != nil {
		t.Fatalf("parseActionForm: %v", err)
	}
	if got := req.Form.Get("alert_rules[memory_high][threshold]"); got != "85" {
		t.Errorf("threshold = %q, want %q", got, "85")
	}
	if got := req.Form.Get("alert_rules[memory_high][enabled]"); got != "1" {
		t.Errorf("enabled = %q, want %q", got, "1")
	}
}

// TestParseActionForm_Urlencoded は従来の urlencoded も引き続き受けられることを見る。
func TestParseActionForm_Urlencoded(t *testing.T) {
	body := "alert_rules%5Bmemory_high%5D%5Bthreshold%5D=90&ban_ips%5B%5D=192.0.2.1"
	req := httptest.NewRequest(http.MethodPost, "/?api=save_alert_rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := parseActionForm(req); err != nil {
		t.Fatalf("parseActionForm: %v", err)
	}
	if got := req.Form.Get("alert_rules[memory_high][threshold]"); got != "90" {
		t.Errorf("threshold = %q, want %q", got, "90")
	}
	if got := req.Form["ban_ips[]"]; len(got) != 1 || got[0] != "192.0.2.1" {
		t.Errorf("ban_ips[] = %v, want [192.0.2.1]", got)
	}
}

// TestParseActionForm_AfterEarlierParseForm は CSRF 検証などが先に r.ParseForm() を
// 呼んで r.Form を非 nil にしていても、multipart の値が拾えることを見る。
// この順序が実際の経路（auth.VerifyCSRF → action handler）で起きる。
func TestParseActionForm_AfterEarlierParseForm(t *testing.T) {
	req := newMultipartRequest(t, map[string]string{
		"alert_rules[disk_high][threshold]": "92",
	})

	// 先行して呼ばれた側を再現する。multipart なので body は読まれず r.Form は空になる。
	_ = req.ParseForm()
	if got := req.Form.Get("alert_rules[disk_high][threshold]"); got != "" {
		t.Fatalf("前提が崩れている: ParseForm だけで値が取れてしまった (%q)", got)
	}

	if err := parseActionForm(req); err != nil {
		t.Fatalf("parseActionForm: %v", err)
	}
	if got := req.Form.Get("alert_rules[disk_high][threshold]"); got != "92" {
		t.Errorf("threshold = %q, want %q", got, "92")
	}
}
