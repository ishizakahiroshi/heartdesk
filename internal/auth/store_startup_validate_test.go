package auth

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ValidateAllOrFatal は不正な設定で log.Fatalf（exit 1）する。同じテストバイナリを
// 子プロセスとして再実行して、終了コードとエラー文を確かめる。
const startupValidateChildEnv = "HEARTDESK_TEST_VALIDATE_USERS_PATH"

func TestValidateAllOrFatalChild(t *testing.T) {
	path := os.Getenv(startupValidateChildEnv)
	if path == "" {
		t.Skip("子プロセス専用")
	}
	(&UserStore{path: path, users: map[string]User{}}).ValidateAllOrFatal()
	// Fatal にならなければここへ到達する。
	os.Stdout.WriteString("VALIDATE_RETURNED\n")
}

func runValidateChild(t *testing.T, usersPath string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestValidateAllOrFatalChild$", "-test.v")
	cmd.Env = append(os.Environ(), startupValidateChildEnv+"="+usersPath)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestValidateAllOrFatalAtStartup(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "valid.toml")
	if err := os.WriteFile(valid, []byte(`
[[users]]
id = "alice"
username = "alice"
name = "Alice"
password_hash = "bcrypt$dummy"
role = "vendor_staff"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "legacy.toml")
	if err := os.WriteFile(legacy, []byte(`
[[users]]
id = "bob"
username = "bob"
name = "Bob"
password_hash = "bcrypt$dummy"
role = "tenant_user"
access_ok_roles = ["monitor"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	badRole := filepath.Join(dir, "badrole.toml")
	if err := os.WriteFile(badRole, []byte(`
[[users]]
username = "carol"
password_hash = "bcrypt$dummy"
role = "not_a_role"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(dir, "broken.toml")
	if err := os.WriteFile(broken, []byte("[[users]\nusername = "), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("正しい設定は起動を妨げない", func(t *testing.T) {
		out, err := runValidateChild(t, valid)
		if err != nil || !strings.Contains(out, "VALIDATE_RETURNED") {
			t.Fatalf("want return, err=%v out=%s", err, out)
		}
	})
	t.Run("users.toml が無い構成は継続する", func(t *testing.T) {
		out, err := runValidateChild(t, filepath.Join(dir, "missing.toml"))
		if err != nil || !strings.Contains(out, "VALIDATE_RETURNED") {
			t.Fatalf("want return, err=%v out=%s", err, out)
		}
	})
	for name, tc := range map[string]struct{ path, want string }{
		"旧スキーマは分かりやすいエラーで止まる": {legacy, "access_ok_roles"},
		"無効な role は止まる":       {badRole, "not_a_role"},
		"TOML 解析失敗は止まる":       {broken, "TOML 解析失敗"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := runValidateChild(t, tc.path)
			if err == nil {
				t.Fatalf("want non-zero exit, out=%s", out)
			}
			if strings.Contains(out, "VALIDATE_RETURNED") {
				t.Fatalf("must not return, out=%s", out)
			}
			if !strings.Contains(out, "[FATAL]") || !strings.Contains(out, tc.want) {
				t.Fatalf("want [FATAL] and %q in output, got %s", tc.want, out)
			}
		})
	}
}
