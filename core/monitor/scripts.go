package monitor

import (
	"path/filepath"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

// binDir は heartdesk 自身の実行スクリプト置き場。HEARTDESK_BASE_DIR 基準（未設定なら /var/lib/heartdesk/bin）。
func binDir() string {
	return heartdesk.PathOrDefault("bin")
}

func scriptCheckAlerts() string {
	return filepath.Join(binDir(), "heartdesk-alerts")
}
