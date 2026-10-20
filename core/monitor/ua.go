package monitor

import (
	"regexp"
	"strings"
)

// UAInfo はUser-Agent解析結果を保持する（parse_user_agent_info() 相当）
type UAInfo struct {
	Device string `json:"device"` // "mobile" / "pc" / "tool" / "scanner" / "unknown"
	Label  string `json:"label"`  // 例: "Chrome 147 / Windows"
}

var (
	reNCAndroid = regexp.MustCompile(`(?i)Nextcloud-android/([\d.]+)`)
	reNCIOS     = regexp.MustCompile(`(?i)Nextcloud-iOS/([\d.]+)`)
	reMirall    = regexp.MustCompile(`(?i)Mirall/([\d.]+)`)
	reCurl      = regexp.MustCompile(`(?i)curl/([\d.]+)`)
	reWget      = regexp.MustCompile(`(?i)wget/([\d.]+)`)
	rePyReq     = regexp.MustCompile(`(?i)python-requests/([\d.]+)`)
	rePyHttpx   = regexp.MustCompile(`(?i)python-httpx/([\d.]+)`)
	reGoHTTP    = regexp.MustCompile(`(?i)Go-http-client/([\d.]+)`)
	reEdge      = regexp.MustCompile(`Edg/([\d.]+)`)
	reOpera     = regexp.MustCompile(`OPR/([\d.]+)`)
	reFirefox   = regexp.MustCompile(`Firefox/([\d.]+)`)
	reChrome    = regexp.MustCompile(`Chrome/([\d.]+)`)
	reSafari    = regexp.MustCompile(`Version/([\d.]+).*Safari`)
)

// ParseUA はUser-Agent文字列を解析してUAInfoを返す（parse_user_agent_info()相当）
func ParseUA(ua string) UAInfo {
	if ua == "" || ua == "-" {
		return UAInfo{Device: "unknown", Label: "UA不明"}
	}

	// Nextcloud 公式クライアント
	if m := reNCAndroid.FindStringSubmatch(ua); m != nil {
		return UAInfo{Device: "mobile", Label: "Nextcloud Android " + m[1]}
	}
	if m := reNCIOS.FindStringSubmatch(ua); m != nil {
		return UAInfo{Device: "mobile", Label: "Nextcloud iOS " + m[1]}
	}
	if m := reMirall.FindStringSubmatch(ua); m != nil {
		return UAInfo{Device: "pc", Label: "Nextcloud Desktop " + m[1]}
	}
	if containsCI(ua, "Nextcloud-Talk") {
		return UAInfo{Device: "mobile", Label: "Nextcloud Talk"}
	}

	// 既知のセキュリティスキャナ
	scanners := []struct{ key, label string }{
		{"Nuclei", "Nuclei"}, {"zgrab", "zgrab"}, {"masscan", "masscan"},
		{"nikto", "Nikto"}, {"sqlmap", "sqlmap"}, {"nmap", "Nmap"},
		{"shodan", "Shodan"}, {"censys", "Censys"}, {"acunetix", "Acunetix"},
		{"dirbuster", "DirBuster"}, {"gobuster", "Gobuster"}, {"wfuzz", "WFuzz"},
		{"burp", "Burp Suite"}, {"metasploit", "Metasploit"}, {"nessus", "Nessus"},
		{"openvas", "OpenVAS"},
	}
	for _, s := range scanners {
		if containsCI(ua, s.key) {
			return UAInfo{Device: "scanner", Label: s.label}
		}
	}

	// HTTP ツール・ライブラリ
	if m := reCurl.FindStringSubmatch(ua); m != nil {
		return UAInfo{Device: "tool", Label: "curl " + m[1]}
	}
	if m := reWget.FindStringSubmatch(ua); m != nil {
		return UAInfo{Device: "tool", Label: "wget " + m[1]}
	}
	if m := rePyReq.FindStringSubmatch(ua); m != nil {
		return UAInfo{Device: "tool", Label: "Python-requests"}
	}
	if m := rePyHttpx.FindStringSubmatch(ua); m != nil {
		return UAInfo{Device: "tool", Label: "Python-httpx"}
	}
	if containsCI(ua, "python") {
		return UAInfo{Device: "tool", Label: "Python"}
	}
	if m := reGoHTTP.FindStringSubmatch(ua); m != nil {
		return UAInfo{Device: "tool", Label: "Go-http"}
	}
	if containsCI(ua, "Go-http") {
		return UAInfo{Device: "tool", Label: "Go-http"}
	}
	tools := []struct{ key, label string }{
		{"libwww-perl", "libwww-perl"}, {"okhttp", "OkHttp"}, {"java/", "Java"},
		{"axios", "axios"}, {"node-fetch", "Node.js"}, {"scrapy", "Scrapy"},
		{"libredtail", "libredtail-http"},
	}
	for _, t := range tools {
		if containsCI(ua, t.key) {
			return UAInfo{Device: "tool", Label: t.label}
		}
	}

	// OS 判定
	os := ""
	switch {
	case containsCI(ua, "iPhone"):
		os = "iPhone"
	case containsCI(ua, "iPad"):
		os = "iPad"
	case containsCI(ua, "Android"):
		os = "Android"
	case containsCI(ua, "Windows"):
		os = "Windows"
	case containsCI(ua, "Mac OS X") || containsCI(ua, "Macintosh"):
		os = "macOS"
	case containsCI(ua, "Linux"):
		os = "Linux"
	}

	// ブラウザ判定（順序重要: Edge → Opera → Firefox → Chrome → Safari）
	br := ""
	switch {
	case reEdge.MatchString(ua):
		if m := reEdge.FindStringSubmatch(ua); m != nil {
			br = "Edge " + majorVersion(m[1])
		}
	case reOpera.MatchString(ua):
		if m := reOpera.FindStringSubmatch(ua); m != nil {
			br = "Opera " + majorVersion(m[1])
		}
	case reFirefox.MatchString(ua):
		if m := reFirefox.FindStringSubmatch(ua); m != nil {
			br = "Firefox " + majorVersion(m[1])
		}
	case reChrome.MatchString(ua):
		if m := reChrome.FindStringSubmatch(ua); m != nil {
			br = "Chrome " + majorVersion(m[1])
		}
	case reSafari.MatchString(ua):
		if m := reSafari.FindStringSubmatch(ua); m != nil {
			br = "Safari " + majorVersion(m[1])
		}
	}

	isMobile := os == "iPhone" || os == "iPad" || os == "Android" || containsCI(ua, "Mobile")
	device := "unknown"
	if isMobile {
		device = "mobile"
	} else if br != "" || os != "" {
		device = "pc"
	}
	label := strings.TrimSpace(func() string {
		if br == "" {
			br = "その他"
		}
		if os != "" {
			return br + " / " + os
		}
		return br
	}())
	return UAInfo{Device: device, Label: label}
}

func containsCI(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// majorVersion は "147.0.1" → "147" を返す
func majorVersion(v string) string {
	if idx := strings.Index(v, "."); idx >= 0 {
		return v[:idx]
	}
	return v
}
