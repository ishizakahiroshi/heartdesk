package monitor

import "testing"

func TestAvatarSafeName(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{"alice", true},
		{"user.name-01@example", true},
		{" 山田 ", true},
		{"", false},
		{".", false},
		{"..", false},
		{"../admin", false},
		{`user\admin`, false},
		{"bad\x00name", false},
	}
	for _, tt := range tests {
		got, ok := avatarSafeName(tt.name)
		if ok != tt.ok {
			t.Fatalf("avatarSafeName(%q) ok = %v, want %v", tt.name, ok, tt.ok)
		}
		if ok && got == "" {
			t.Fatalf("avatarSafeName(%q) returned empty safe name", tt.name)
		}
	}
}
