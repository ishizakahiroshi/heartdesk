//go:build !linux

package daemon

import "os"

// extractInode は非 Linux 環境では inode を取得できないため 0 を返すスタブ。
// 本番（Ubuntu/Linux）では extract_inode_linux.go の実装が使われる。
func extractInode(fi os.FileInfo) uint64 {
	_ = fi
	return 0
}
