package monitor

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fail2ban の BAN / UNBAN 系の成否判定のテスト。実システムの fail2ban-client / sudo は呼ばず、
// 実行器 fail2banRun を差し替えて確かめる。

// fakeF2B は fail2ban-client の実行を差し替えるテスト用の実行器。
type fakeF2B struct {
	mu    sync.Mutex
	calls [][]string
	// reply は 1 回の実行（引数は "/usr/bin/fail2ban-client" 以降）に対する出力とエラーを返す。
	reply func(args []string) (string, error)
}

func (f *fakeF2B) install(t *testing.T) {
	t.Helper()
	orig := fail2banRun
	fail2banRun = func(_ time.Duration, cmd string, args ...string) (string, error) {
		if cmd != "sudo" || len(args) == 0 || args[0] != "/usr/bin/fail2ban-client" {
			t.Errorf("想定外のコマンド: %s %v", cmd, args)
			return "", errors.New("unexpected command")
		}
		f.mu.Lock()
		f.calls = append(f.calls, append([]string(nil), args[1:]...))
		f.mu.Unlock()
		return f.reply(args[1:])
	}
	t.Cleanup(func() { fail2banRun = orig })
}

// setupManualBanDir は appendManualBan の書き込み先を一時ディレクトリにする。
func setupManualBanDir(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	if err := os.MkdirAll(filepath.Join(base, "data", "json"), 0o755); err != nil {
		t.Fatal(err)
	}
	return base
}

func manualBanLog(t *testing.T, base string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(base, "data", "json", "manual_bans_log.csv"))
	if err != nil {
		return ""
	}
	return string(raw)
}

func postAction(t *testing.T, handler func(http.ResponseWriter, *http.Request), form url.Values) (int, ActionResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)
	var resp ActionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("応答が JSON ではない: %q (%v)", rec.Body.String(), err)
	}
	return rec.Code, resp
}

var errExit1 = errors.New("exit status 1")

// ---- OPS-1: UnbanIP が失敗を無視して成功を返す ----

func TestUnbanIPAllJailsFail(t *testing.T) {
	(&fakeF2B{reply: func([]string) (string, error) {
		return "sudo: a password is required", errExit1
	}}).install(t)

	err := UnbanIP("203.0.113.5", "")
	if err == nil {
		t.Fatal("全 jail が失敗したのに nil（成功）を返した")
	}
	if !strings.Contains(err.Error(), "a password is required") {
		t.Errorf("失敗理由が含まれていない: %v", err)
	}
}

func TestUnbanIPSingleJailFail(t *testing.T) {
	(&fakeF2B{reply: func([]string) (string, error) {
		return "", errExit1
	}}).install(t)

	if err := UnbanIP("203.0.113.5", "recidive"); err == nil {
		t.Fatal("jail 指定の UNBAN が失敗したのに nil（成功）を返した")
	}
}

func TestUnbanIPPartialFailureNamesBothSides(t *testing.T) {
	(&fakeF2B{reply: func(args []string) (string, error) {
		if args[1] == "recidive" {
			return "NOK: jail recidive error", errExit1
		}
		return "1", nil
	}}).install(t)

	err := UnbanIP("203.0.113.5", "")
	if err == nil {
		t.Fatal("一部の jail が失敗したのに nil（成功）を返した")
	}
	msg := err.Error()
	for _, want := range []string{"成功", "nextcloud", "失敗", "recidive", "jail recidive error"} {
		if !strings.Contains(msg, want) {
			t.Errorf("メッセージに %q が無い: %s", want, msg)
		}
	}
}

func TestUnbanIPNotBannedIsNotFailure(t *testing.T) {
	// 全 jail 指定のとき、BAN されていない jail が「not banned」で非 0 終了しても失敗としない。
	(&fakeF2B{reply: func(args []string) (string, error) {
		if args[1] == "nextcloud" {
			return "1", nil
		}
		return "NOK: ('203.0.113.5 is not banned',)", errExit1
	}}).install(t)

	if err := UnbanIP("203.0.113.5", ""); err != nil {
		t.Fatalf("not banned を失敗扱いした: %v", err)
	}
}

func TestUnbanIPSuccess(t *testing.T) {
	f := &fakeF2B{reply: func([]string) (string, error) { return "1", nil }}
	f.install(t)
	if err := UnbanIP("203.0.113.5", ""); err != nil {
		t.Fatalf("全 jail 成功なのにエラー: %v", err)
	}
	if len(f.calls) != len(jailNames) {
		t.Errorf("実行回数 = %d, want %d", len(f.calls), len(jailNames))
	}
}

func TestActionFail2banUnbanReportsFailureToClient(t *testing.T) {
	(&fakeF2B{reply: func([]string) (string, error) { return "boom", errExit1 }}).install(t)
	h := &Handler{}

	for name, form := range map[string]url.Values{
		"全 jail":  {"ip": {"203.0.113.5"}},
		"jail 指定": {"ip": {"203.0.113.5"}, "jail": {"recidive"}},
	} {
		code, resp := postAction(t, h.actionFail2banUnban, form)
		if code != http.StatusBadRequest || resp.OK {
			t.Errorf("%s: code=%d ok=%v, want 400 / ok=false (message=%q)", name, code, resp.OK, resp.Message)
		}
		if strings.Contains(resp.Message, "UNBAN しました") {
			t.Errorf("%s: 失敗なのに成功のメッセージを返した: %q", name, resp.Message)
		}
	}
}

// ---- OPS-2: BAN 失敗の理由が空 / bulk_ban が全件失敗でも ok:true ----

func TestBanIPFailureCarriesReason(t *testing.T) {
	base := setupManualBanDir(t)
	(&fakeF2B{reply: func([]string) (string, error) {
		return "sudo: a password is required", errExit1
	}}).install(t)

	err := BanIP("203.0.113.7")
	if err == nil {
		t.Fatal("失敗したのに nil を返した")
	}
	if !strings.Contains(err.Error(), "a password is required") {
		t.Errorf("失敗理由（コマンドの出力）が含まれていない: %q", err.Error())
	}
	if got := manualBanLog(t, base); got != "" {
		t.Errorf("失敗したのに手動 BAN ログへ記録された: %q", got)
	}
}

func TestBanIPFailureWithoutOutputStillHasReason(t *testing.T) {
	setupManualBanDir(t)
	(&fakeF2B{reply: func([]string) (string, error) { return "", errExit1 }}).install(t)

	err := BanIP("203.0.113.7")
	if err == nil || !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("出力が空でも理由（終了状態）を含めるべき: %v", err)
	}
}

func TestBanIPSuccessRecordsManualBan(t *testing.T) {
	base := setupManualBanDir(t)
	(&fakeF2B{reply: func([]string) (string, error) { return "1", nil }}).install(t)

	if err := BanIP("203.0.113.7"); err != nil {
		t.Fatalf("成功なのにエラー: %v", err)
	}
	if !strings.Contains(manualBanLog(t, base), "203.0.113.7") {
		t.Error("成功した BAN が手動 BAN ログへ記録されていない")
	}
}

func bulkBanForm(ips ...string) url.Values {
	return url.Values{"ban_ips[]": ips}
}

func TestBulkBanAllFailIsErrorResponse(t *testing.T) {
	setupManualBanDir(t)
	(&fakeF2B{reply: func([]string) (string, error) {
		return "permission denied", errExit1
	}}).install(t)
	h := &Handler{}

	code, resp := postAction(t, h.actionBulkBan, bulkBanForm("203.0.113.7", "203.0.113.8"))
	if code != http.StatusBadRequest || resp.OK {
		t.Fatalf("全件失敗: code=%d ok=%v, want 400 / ok=false (message=%q)", code, resp.OK, resp.Message)
	}
	for _, want := range []string{"203.0.113.7", "203.0.113.8", "permission denied"} {
		if !strings.Contains(resp.Message, want) {
			t.Errorf("メッセージに %q が無い: %q", want, resp.Message)
		}
	}
}

func TestBulkBanPartialFailureIsNotOK(t *testing.T) {
	base := setupManualBanDir(t)
	(&fakeF2B{reply: func(args []string) (string, error) {
		if args[len(args)-1] == "203.0.113.8" {
			return "permission denied", errExit1
		}
		return "1", nil
	}}).install(t)
	h := &Handler{}

	code, resp := postAction(t, h.actionBulkBan, bulkBanForm("203.0.113.7", "203.0.113.8"))
	if resp.OK {
		t.Fatalf("一部失敗なのに ok:true (code=%d message=%q)", code, resp.Message)
	}
	if code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", code)
	}
	for _, want := range []string{"成功 1 件", "失敗 1 件", "203.0.113.8", "permission denied"} {
		if !strings.Contains(resp.Message, want) {
			t.Errorf("メッセージに %q が無い: %q", want, resp.Message)
		}
	}
	if !strings.Contains(manualBanLog(t, base), "203.0.113.7") {
		t.Error("成功した分が手動 BAN ログへ記録されていない")
	}
}

func TestBulkBanAllSuccessIsOK(t *testing.T) {
	setupManualBanDir(t)
	(&fakeF2B{reply: func([]string) (string, error) { return "1", nil }}).install(t)
	h := &Handler{}

	code, resp := postAction(t, h.actionBulkBan, bulkBanForm("203.0.113.7", "203.0.113.8"))
	if code != http.StatusOK || !resp.OK {
		t.Fatalf("全件成功: code=%d ok=%v message=%q", code, resp.OK, resp.Message)
	}
}

func TestActionFail2banBanFailureHasReason(t *testing.T) {
	setupManualBanDir(t)
	(&fakeF2B{reply: func([]string) (string, error) {
		return "sudo: a password is required", errExit1
	}}).install(t)
	h := &Handler{}

	code, resp := postAction(t, h.actionFail2banBan, url.Values{"ip": {"203.0.113.7"}})
	if code != http.StatusBadRequest || resp.OK {
		t.Fatalf("code=%d ok=%v", code, resp.OK)
	}
	if !strings.Contains(resp.Message, "a password is required") {
		t.Errorf("理由が空: %q", resp.Message)
	}
}

// ---- OPS-5: BanHighScore が出力に "1" / "OK" を含むかで成功を判定する ----

func TestBanHighScoreNOKWithExitZeroIsFailure(t *testing.T) {
	base := setupManualBanDir(t)
	(&fakeF2B{reply: func([]string) (string, error) {
		return "NOK: Sorry but the jail recidive does not exist", nil
	}}).install(t)

	if err := BanHighScore("203.0.113.9"); err == nil {
		t.Fatal("NOK を成功と判定した")
	}
	if got := manualBanLog(t, base); got != "" {
		t.Errorf("失敗したのに手動 BAN ログへ記録された: %q", got)
	}
}

func TestBanHighScoreNonZeroExitIsFailureEvenIfOutputHasDigit(t *testing.T) {
	setupManualBanDir(t)
	(&fakeF2B{reply: func([]string) (string, error) {
		return "ERROR 1 occurred", errExit1
	}}).install(t)

	err := BanHighScore("203.0.113.9")
	if err == nil {
		t.Fatal("終了コード非 0 なのに、出力に \"1\" があるため成功と判定した")
	}
	if !strings.Contains(err.Error(), "ERROR 1 occurred") {
		t.Errorf("理由（出力）が含まれていない: %v", err)
	}
}

func TestBanHighScoreSuccessByExitCode(t *testing.T) {
	base := setupManualBanDir(t)
	// 出力が空や "0"（既に BAN 済み）でも、終了コード 0 なら成功。
	(&fakeF2B{reply: func([]string) (string, error) { return "0", nil }}).install(t)

	if err := BanHighScore("203.0.113.9"); err != nil {
		t.Fatalf("終了コード 0 なのに失敗扱い: %v", err)
	}
	if !strings.Contains(manualBanLog(t, base), "203.0.113.9") {
		t.Error("成功した BAN が手動 BAN ログへ記録されていない")
	}
}

// ---- OPS-6: toggle_auto_update が mode=enable 以外をすべて無効化と解釈する ----

func TestParseAutoUpdateMode(t *testing.T) {
	cases := []struct {
		in         string
		enable, ok bool
	}{
		{"enable", true, true},
		{" enable ", true, true},
		{"disable", false, true},
		{"", false, false},
		{"bogus", false, false},
		{"ENABLE", false, false},
		{"1", false, false},
	}
	for _, c := range cases {
		enable, ok := parseAutoUpdateMode(c.in)
		if enable != c.enable || ok != c.ok {
			t.Errorf("parseAutoUpdateMode(%q) = (%v, %v), want (%v, %v)", c.in, enable, ok, c.enable, c.ok)
		}
	}
}

func TestActionToggleAutoUpdateRejectsUnknownMode(t *testing.T) {
	h := &Handler{}
	for _, mode := range []string{"bogus", ""} {
		code, resp := postAction(t, h.actionToggleAutoUpdate, url.Values{"mode": {mode}})
		if code != http.StatusBadRequest || resp.OK {
			t.Errorf("mode=%q: code=%d ok=%v, want 400 / ok=false (message=%q)", mode, code, resp.OK, resp.Message)
		}
	}
}
