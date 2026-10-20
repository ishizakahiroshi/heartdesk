//go:build windows

package filelock

import "errors"

// ErrLocked は Unix 実装と同じ sentinel。非 Unix では flock を使わないため返さないが、
// 型を揃えて errors.Is 判定が両プラットフォームでコンパイルできるようにする。
var ErrLocked = errors.New("filelock: already locked")

// Acquire は非 Unix 環境では no-op（多重起動防止なし）。
// heartdesk 本番は Linux のため production の排他は Unix 実装で担保する。
// Windows はローカルビルド／テスト用で、解放用クロージャも no-op を返す。
func Acquire(path string) (func(), error) {
	return func() {}, nil
}

// TryAcquire は Acquire の別名（非 Unix では no-op）。
func TryAcquire(path string) (func(), error) {
	return Acquire(path)
}
