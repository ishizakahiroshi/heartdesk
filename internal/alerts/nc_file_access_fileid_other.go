//go:build !unix

package alerts

import "os"

// ncFAFileIDFromInfo は inode を取れない環境（Windows 等）では常に ok=false を返す。
// その場合の切り替わりの判定は「サイズが記録位置より小さいか」だけになる。
func ncFAFileIDFromInfo(os.FileInfo) (uint64, bool) {
	return 0, false
}
