package auth

import (
	"net/http"
	"testing"
)

func TestTrustedClientIP(t *testing.T) {
	// 既定（ループバックのみ信頼）に戻す。
	SetTrustedProxies(nil)

	tests := []struct {
		name       string
		remoteAddr string
		xRealIP    string
		xff        string
		want       string
	}{
		{
			name:       "loopback proxy trusts X-Real-IP",
			remoteAddr: "127.0.0.1:5555",
			xRealIP:    "203.0.113.7",
			want:       "203.0.113.7",
		},
		{
			name:       "loopback proxy trusts X-Forwarded-For left-most",
			remoteAddr: "127.0.0.1:5555",
			xff:        "203.0.113.8, 198.51.100.1",
			want:       "203.0.113.8",
		},
		{
			name:       "direct connection ignores spoofed X-Real-IP",
			remoteAddr: "198.51.100.9:4444",
			xRealIP:    "203.0.113.7",
			want:       "198.51.100.9",
		},
		{
			name:       "direct connection ignores spoofed XFF",
			remoteAddr: "198.51.100.9:4444",
			xff:        "203.0.113.7",
			want:       "198.51.100.9",
		},
		{
			name:       "loopback proxy without headers falls back to remote host",
			remoteAddr: "127.0.0.1:5555",
			want:       "127.0.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := TrustedClientIP(r); got != tt.want {
				t.Fatalf("TrustedClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTrustedClientIP_ConfiguredProxy(t *testing.T) {
	SetTrustedProxies([]string{"198.51.100.0/24"})
	t.Cleanup(func() { SetTrustedProxies(nil) })

	tests := []struct {
		name       string
		remoteAddr string
		xRealIP    string
		want       string
	}{
		{
			name:       "configured proxy CIDR trusts header",
			remoteAddr: "198.51.100.7:80",
			xRealIP:    "203.0.113.7",
			want:       "203.0.113.7",
		},
		{
			name:       "non-proxy direct still ignores header",
			remoteAddr: "192.0.2.1:80",
			xRealIP:    "203.0.113.7",
			want:       "192.0.2.1",
		},
		{
			name:       "loopback still trusted alongside configured proxy",
			remoteAddr: "127.0.0.1:80",
			xRealIP:    "203.0.113.7",
			want:       "203.0.113.7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if got := TrustedClientIP(r); got != tt.want {
				t.Fatalf("TrustedClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
