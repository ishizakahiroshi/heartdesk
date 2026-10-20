//go:build !windows

package filelock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ErrLocked はロックが他プロセス／他スレッドに保持されており取得できなかったことを表す
// sentinel error（flock の EWOULDBLOCK 由来）。open 失敗（権限不足・パス不正）とは区別する。
// 呼び出し側は errors.Is(err, ErrLocked) で「実行中スキップ」を判定し、それ以外の error は
// 本物の I/O/権限エラーとして伝播させる（C4: ondemand-apt-lock-silent-skip）。
var ErrLocked = errors.New("filelock: already locked")

// Acquire はロックファイルに排他 flock を取得する（非ブロッキング）。
// 取得できた場合は解放用クロージャを返す。
//
// 競合（既にロック保持）時は ErrLocked を返す。open 失敗等はその error をそのまま返す。
// これにより呼び出し側は errors.Is(err, ErrLocked) でロック競合と I/O エラーを区別できる。
func Acquire(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("flock: %w", err)
	}
	// 注: ロックファイル自体は意図的に削除しない。flock 状態は Close で解放されるため
	// ファイルを残しても次回取得に支障はなく、削除と解放の競合を避けられる。
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// TryAcquire は Acquire の別名（非ブロッキング取得）。
// per-job ロック（scheduler.execute）で意図を明示するために用意する。
func TryAcquire(path string) (func(), error) {
	return Acquire(path)
}
