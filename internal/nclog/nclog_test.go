package nclog

import "testing"

func TestExtractUserCreated(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want string
	}{
		{"double quoted", `User created: "alice"`, "alice"},
		{"single quoted", `User created: 'alice'`, "alice"},
		{"unrelated message", `Login successful: "alice"`, ""},
		{"empty message", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractUserCreated(tc.msg); got != tc.want {
				t.Fatalf("ExtractUserCreated(%q) = %q, want %q", tc.msg, got, tc.want)
			}
		})
	}
}

func TestExtractLoginResult(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want string
	}{
		{"successful", `Login successful: "alice"`, "success"},
		{"succeeded", `Login succeeded: "alice"`, "success"},
		{"successful login", `Successful login: "alice"`, "success"},
		{"failed", `Login failed: "alice"`, "fail"},
		{"failure", `Login failure: "alice"`, "fail"},
		{"user created is not a login", `User created: "alice"`, ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractLoginResult(tc.msg); got != tc.want {
				t.Fatalf("ExtractLoginResult(%q) = %q, want %q", tc.msg, got, tc.want)
			}
		})
	}
}

func TestExtractLoginUserFromMessage(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want string
	}{
		{"successful double quoted", `Login successful: "bob@example.com"`, "bob@example.com"},
		{"failed single quoted", `Login failed: 'alice'`, "alice"},
		{"successful login form", `Successful login: "alice"`, "alice"},
		{"no user", `Bruteforce attempt from "1.2.3.4"`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractLoginUserFromMessage(tc.msg); got != tc.want {
				t.Fatalf("ExtractLoginUserFromMessage(%q) = %q, want %q", tc.msg, got, tc.want)
			}
		})
	}
}

func TestParseTime(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"rfc3339 with offset", "2026-08-31T09:00:00+09:00", true},
		{"rfc3339 zulu", "2026-08-30T23:14:14Z", true},
		{"space separated", "2026-08-31 09:00:00", true},
		{"empty", "", false},
		{"garbage", "not-a-time", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := ParseTime(tc.in); ok != tc.ok {
				t.Fatalf("ParseTime(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			}
		})
	}
}
