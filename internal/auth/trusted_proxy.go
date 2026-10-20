package auth

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

// trustedProxy 層（C3: trust-xff-ip-spoofing / x-real-ip-trusted-unconditionally）。
//
// X-Real-IP / X-Forwarded-For は、直接の TCP 接続元（RemoteAddr）が信頼できる
// リバースプロキシ（nginx 等）であるときに限り採用する。:8765 へ nginx を迂回して
// 直結された場合はヘッダを信用せず RemoteAddr を使うため、ヘッダ偽装による
// ロックアウト回避・IP allowlist 突破・PIN ロック回避が成立しない。
//
// 信頼プロキシは既定でループバック（127.0.0.0/8, ::1）のみ。heartdesk は通常 nginx から
// 127.0.0.1:8765 へプロキシされるため既定で十分。追加のプロキシ IP / CIDR は
// [security].trusted_proxies で指定し、起動時に SetTrustedProxies で登録する。

var (
	trustedProxyMu   sync.RWMutex
	trustedProxyNets []*net.IPNet
)

// loopbackCIDRs は既定で常に信頼するループバック範囲。
func loopbackCIDRs() []*net.IPNet {
	nets := make([]*net.IPNet, 0, 2)
	for _, c := range []string{"127.0.0.0/8", "::1/128"} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

// SetTrustedProxies は信頼するリバースプロキシの IP / CIDR を登録する（起動時に 1 回）。
// ループバックは常に信頼されるため、ここには nginx 等の追加 IP のみを渡せばよい。
// 不正なエントリは無視する。
func SetTrustedProxies(entries []string) {
	nets := loopbackCIDRs()
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			if _, n, err := net.ParseCIDR(e); err == nil {
				nets = append(nets, n)
			}
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	trustedProxyMu.Lock()
	trustedProxyNets = nets
	trustedProxyMu.Unlock()
}

// isTrustedProxy は host（ポートなし IP 文字列）が信頼プロキシ範囲かを返す。
func isTrustedProxy(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	trustedProxyMu.RLock()
	nets := trustedProxyNets
	trustedProxyMu.RUnlock()
	if nets == nil {
		nets = loopbackCIDRs()
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// remoteAddrHost は r.RemoteAddr から host 部（ポート除去）を返す。
func remoteAddrHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

// TrustedClientIP はクライアント IP を信頼境界を考慮して返す。
//
//   - RemoteAddr が信頼プロキシ（loopback / 登録 nginx）のときのみ X-Real-IP →
//     X-Forwarded-For（左端）の順でヘッダを採用する。
//   - それ以外（:8765 直結等）は RemoteAddr の host を使い、ヘッダは無視する。
//
// 返り値はポートを除いた IP 文字列。判定できない場合は空文字。
func TrustedClientIP(r *http.Request) string {
	host := remoteAddrHost(r)
	if !isTrustedProxy(host) {
		return host
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		// 左端（最も外側のクライアント）を採用する。
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return xff
	}
	return host
}
