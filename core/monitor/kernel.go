package monitor

import "github.com/ishizakahiroshi/heartdesk/internal"

// GetKernel は稼働中カーネルと最新カーネルのバージョンを返す
func GetKernel() KernelInfo {
	current := heartdesk.Run("uname -r")
	latest := heartdesk.Run("ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -1 | sed 's|/boot/vmlinuz-||'")
	return KernelInfo{
		Current:  current,
		Latest:   latest,
		Outdated: current != "" && latest != "" && current != latest,
	}
}
