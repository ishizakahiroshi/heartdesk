package monitor

import sab "github.com/ishizakahiroshi/heartdesk/internal"

// GetKernel は稼働中カーネルと最新カーネルのバージョンを返す
func GetKernel() KernelInfo {
	current := sab.Run("uname -r")
	latest := sab.Run("ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -1 | sed 's|/boot/vmlinuz-||'")
	return KernelInfo{
		Current:  current,
		Latest:   latest,
		Outdated: current != "" && latest != "" && current != latest,
	}
}
