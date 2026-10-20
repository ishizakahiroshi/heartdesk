package auth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestDummyBcryptHashValid は C5（username-enum-timing）のダミーハッシュが
// 有効な bcrypt ハッシュとして生成されていることを確認する。
// これにより不在/Disabled ユーザーでも実ユーザーと同等の bcrypt 計算が走る。
func TestDummyBcryptHashValid(t *testing.T) {
	if dummyBcryptHash == nil {
		t.Fatal("dummyBcryptHash must be generated at package init")
	}
	if _, err := bcrypt.Cost(dummyBcryptHash); err != nil {
		t.Fatalf("dummyBcryptHash is not a valid bcrypt hash: %v", err)
	}
	// 任意パスワードに対して比較が走ること（panic しない・false を返す）。
	runDummyPasswordCompare("anything")
}
