package filelock

import (
	"errors"
	"fmt"
	"testing"
)

// TestErrLockedIsSentinel は ErrLocked が errors.Is で識別可能な sentinel であり、
// 無関係なエラー（open 失敗等）と区別できることを保証する。
// apt_update.go はこの区別に依存して「既に実行中（already_running）」と
// 本物の I/O/権限エラーを分岐するため、sentinel の性質が崩れないことを固定する。
func TestErrLockedIsSentinel(t *testing.T) {
	if !errors.Is(ErrLocked, ErrLocked) {
		t.Fatal("ErrLocked should match itself via errors.Is")
	}
	wrapped := fmt.Errorf("apt lock: %w", ErrLocked)
	if !errors.Is(wrapped, ErrLocked) {
		t.Fatal("wrapped ErrLocked should be detectable via errors.Is")
	}
	other := errors.New("permission denied")
	if errors.Is(other, ErrLocked) {
		t.Fatal("unrelated error must not match ErrLocked")
	}
}

// TestAcquireReleaseRoundTrip は同一プロセス内で取得→解放→再取得できることを確認する。
func TestAcquireReleaseRoundTrip(t *testing.T) {
	path := t.TempDir() + "/round.lock"
	unlock, err := Acquire(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	unlock()
	unlock2, err := Acquire(path)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	unlock2()
}
