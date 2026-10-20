//go:build unix

package alerts

import (
	"os"
	"syscall"
)

// ncFAFileIDFromInfo はファイルの inode を返す（logrotate の create 方式で名前が変わった
// ことを見分けるため）。取れなければ ok=false。
func ncFAFileIDFromInfo(fi os.FileInfo) (uint64, bool) {
	if fi == nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return uint64(st.Ino), true
}
