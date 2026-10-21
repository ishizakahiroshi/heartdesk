package main

import (
	"strings"
	"testing"
)

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestCheckEnv(t *testing.T) {
	cases := []struct {
		name   string
		env    map[string]string
		wantOK bool
		want   []string // 出力に含まれるべき断片
	}{
		{"BASE_DIR だけでよい", map[string]string{"HEARTDESK_BASE_DIR": "/srv/hd"}, true,
			[]string{"OK: HEARTDESK_BASE_DIR=/srv/hd", "is not set (using ", "tenant default"}},
		{"全部ある", map[string]string{"HEARTDESK_BASE_DIR": "/srv/hd", "HEARTDESK_CONFIG_DIR": "/etc/hd", "HEARTDESK_TENANT_ID": "alpha"}, true,
			[]string{"HEARTDESK_CONFIG_DIR=/etc/hd", "HEARTDESK_TENANT_ID=alpha"}},
		{"BASE_DIR が無いと NG", map[string]string{}, false,
			[]string{"NG: HEARTDESK_BASE_DIR is not set"}},
	}
	for _, c := range cases {
		lines, ok := checkEnv(envFrom(c.env))
		if ok != c.wantOK {
			t.Errorf("%s: ok = %v, want %v (%v)", c.name, ok, c.wantOK, lines)
		}
		joined := strings.Join(lines, "\n")
		for _, frag := range c.want {
			if !strings.Contains(joined, frag) {
				t.Errorf("%s: output missing %q:\n%s", c.name, frag, joined)
			}
		}
	}
	// TENANT_ID・CONFIG_DIR が未設定でも NG の行は出ない。
	lines, _ := checkEnv(envFrom(map[string]string{"HEARTDESK_BASE_DIR": "/srv/hd"}))
	for _, l := range lines {
		if strings.HasPrefix(l, "NG:") {
			t.Errorf("unexpected NG line: %q", l)
		}
	}
}
