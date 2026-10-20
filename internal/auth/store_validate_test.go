package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateAndConvertRawReturnsErrorOnLegacyFields は C-013 / C-030 の回帰テスト。
// 旧フィールド（access_ok_roles / permissions / denies / policy）や無効 role が
// 来た場合に log.Fatalf でプロセスを落とさず、error を返すことを確認する。
func TestValidateAndConvertRawReturnsErrorOnLegacyFields(t *testing.T) {
	cases := []struct {
		name     string
		raw      rawUser
		wantSub  string
		wantPass bool
	}{
		{
			name:    "access_ok_roles legacy",
			raw:     rawUser{Username: "u1", Role: "vendor_staff", AccessOKRoles: []string{"monitor"}},
			wantSub: "access_ok_roles",
		},
		{
			name:    "permissions legacy",
			raw:     rawUser{Username: "u2", Role: "vendor_staff", Permissions: []string{"x"}},
			wantSub: "permissions",
		},
		{
			name:    "denies legacy",
			raw:     rawUser{Username: "u3", Role: "vendor_staff", Denies: []string{"x"}},
			wantSub: "denies",
		},
		{
			name:    "policy legacy",
			raw:     rawUser{Username: "u4", Role: "vendor_staff", Policy: map[string]any{"actions": []string{}}},
			wantSub: "policy",
		},
		{
			name:    "invalid role",
			raw:     rawUser{Username: "u5", Role: "not_a_role"},
			wantSub: "role=\"not_a_role\"",
		},
		{
			name:     "valid row",
			raw:      rawUser{Username: "u6", Role: "vendor_staff"},
			wantPass: true,
		},
		{
			name:    "raw bcrypt hash missing prefix",
			raw:     rawUser{Username: "u7", Role: "vendor_staff", PasswordHash: "$2a$12$4pMx10i7108On84nAlUwFuGn8dV99XPG3ySPGNgYKYvHn9ZweePB6"},
			wantSub: "bcrypt$",
		},
		{
			name:     "bcrypt hash with correct prefix",
			raw:      rawUser{Username: "u8", Role: "vendor_staff", PasswordHash: "bcrypt$$2a$12$4pMx10i7108On84nAlUwFuGn8dV99XPG3ySPGNgYKYvHn9ZweePB6"},
			wantPass: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := validateAndConvertRaw(tc.raw)
			if tc.wantPass {
				if err != nil {
					t.Fatalf("want pass, got err=%v", err)
				}
				if u.Username == "" {
					t.Fatalf("want User populated, got empty Username")
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestLoadUsersSkipsBadRowAndKeepsCachedValue は C-013 / C-030 の回帰テスト。
// users.toml に旧フィールドが混入しても (1) プロセスが exit せず、(2) 以前に
// 読み込めた行はキャッシュから温存されることを確認する。
func TestLoadUsersSkipsBadRowAndKeepsCachedValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.toml")

	// 初回: 2 名とも valid
	initialTOML := `
[[users]]
id = "alice"
username = "alice"
name = "Alice"
password_hash = "bcrypt$dummy"
role = "vendor_staff"

[[users]]
id = "bob"
username = "bob"
name = "Bob"
password_hash = "bcrypt$dummy"
role = "tenant_user"
`
	if err := os.WriteFile(path, []byte(initialTOML), 0o600); err != nil {
		t.Fatalf("write initial: %v", err)
	}

	store := &UserStore{path: path, users: map[string]User{}}
	users := store.loadUsers()
	if _, ok := users["alice"]; !ok {
		t.Fatalf("alice missing after initial load")
	}
	if _, ok := users["bob"]; !ok {
		t.Fatalf("bob missing after initial load")
	}

	// 2 回目: bob だけ旧フィールドを混入。TTL を強制的に超過させる。
	corruptTOML := `
[[users]]
id = "alice"
username = "alice"
name = "Alice"
password_hash = "bcrypt$dummy"
role = "vendor_staff"

[[users]]
id = "bob"
username = "bob"
name = "Bob"
password_hash = "bcrypt$dummy"
role = "tenant_user"
access_ok_roles = ["monitor"]
`
	if err := os.WriteFile(path, []byte(corruptTOML), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	// TTL 超過させてリロードを誘発
	store.mu.Lock()
	store.loadedAt = store.loadedAt.Add(-2 * usersCacheTTL)
	store.mu.Unlock()

	users = store.loadUsers()
	// プロセスが exit せず到達できれば C-013 / C-030 の根本回避は OK。
	if _, ok := users["alice"]; !ok {
		t.Fatalf("alice missing after corrupt reload (should still load)")
	}
	// bob はキャッシュから温存される（旧フィールドが付いていてもログアウトさせない）。
	if _, ok := users["bob"]; !ok {
		t.Fatalf("bob missing after corrupt reload: expected cached value to be retained")
	}
}

// TestLoadUsersDropsBadRowWhenNoCache はキャッシュに無い行が旧フィールドを
// 含んでいた場合、その行はスキップされ、他の valid 行は読み込めることを確認する。
func TestLoadUsersDropsBadRowWhenNoCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.toml")

	tomlData := `
[[users]]
id = "alice"
username = "alice"
name = "Alice"
password_hash = "bcrypt$dummy"
role = "vendor_staff"

[[users]]
id = "bob"
username = "bob"
name = "Bob"
password_hash = "bcrypt$dummy"
role = "tenant_user"
permissions = ["x"]
`
	if err := os.WriteFile(path, []byte(tomlData), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	store := &UserStore{path: path, users: map[string]User{}}
	users := store.loadUsers()
	if _, ok := users["alice"]; !ok {
		t.Fatalf("alice missing")
	}
	if _, ok := users["bob"]; ok {
		t.Fatalf("bob should have been skipped (no cached fallback)")
	}
}
