//go:build linux

package daemon

import (
	"os"
	"syscall"
)

// extractInode は Linux で実 inode 番号を返す。
// ログファイルがローテートされると inode が変わるため、呼び出し元は
// state.Inode != extractInode(fi) でローテートを検出し、オフセットをリセットして
// 新ファイルを先頭から読み直す。型アサーション失敗時は 0（rotate 検出スキップ）に
// フォールバックし panic させない。
func extractInode(fi os.FileInfo) uint64 {
	if fi == nil {
		return 0
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0
	}
	return uint64(st.Ino)
}
