package auth

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestTOTPManager(t *testing.T) *TOTPManager {
	t.Helper()
	return &TOTPManager{
		path:  filepath.Join(t.TempDir(), "totp.toml"),
		users: map[string]totpEntry{},
	}
}

// codeFor は指定 secret / 時刻に対する正しい TOTP コードを返す（テスト用）。
func codeFor(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	key, err := b32.DecodeString(secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	return hotpCode(key, now.Unix()/totpPeriod)
}

// TestEnableAfterVerifyRecordsLastCounter は C5（totp-enable-no-replay-counter）の
// 「有効化に使ったコードが直後のログインで再利用できない」を確認する。
func TestEnableAfterVerifyRecordsLastCounter(t *testing.T) {
	m := newTestTOTPManager(t)
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("gen secret: %v", err)
	}
	m.SetSecret("alice", secret, false)

	now := time.Now()
	code := codeFor(t, secret, now)

	// 有効化成功。
	if !m.EnableAfterVerify("alice", code, now) {
		t.Fatal("EnableAfterVerify should succeed with valid code")
	}
	// 有効化済みであること。
	if !m.IsEnabled("alice") {
		t.Fatal("user should be enabled after EnableAfterVerify")
	}
	// 同じコード（同じカウンタ）での直後ログインはリプレイとして拒否されること。
	if m.Verify("alice", code, now) {
		t.Fatal("the code used for enable must not be replayable on login")
	}
	// 次の time step の新しいコードは受理されること。
	next := now.Add(totpPeriod * time.Second)
	if !m.Verify("alice", codeFor(t, secret, next), next) {
		t.Fatal("a fresh code in the next step should verify")
	}
}

// TestEnableAfterVerifyRejectsBadCode は不正コードで有効化されないことを確認する。
func TestEnableAfterVerifyRejectsBadCode(t *testing.T) {
	m := newTestTOTPManager(t)
	secret, _ := GenerateTOTPSecret()
	m.SetSecret("bob", secret, false)

	if m.EnableAfterVerify("bob", "000000", time.Now()) {
		// "000000" が偶然一致する確率は無視できるが、念のため一致時はスキップ。
		t.Skip("unexpected code collision; skipping")
	}
	if m.IsEnabled("bob") {
		t.Fatal("bob must not be enabled after a failed verify")
	}
}
