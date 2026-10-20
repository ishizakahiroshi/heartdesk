package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func legacySHA256Hash(salt []byte, password string) string {
	sum := sha256.Sum256(append(salt, []byte(":"+password)...))
	return "sha256$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(sum[:])
}

func TestVerifyPasswordFormats(t *testing.T) {
	password := "correct horse battery staple"
	bcryptRaw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	shaHash := legacySHA256Hash([]byte("salt"), password)

	tests := []struct {
		name       string
		storedHash string
		password   string
		want       bool
	}{
		{name: "bcrypt ok", storedHash: "bcrypt$" + string(bcryptRaw), password: password, want: true},
		{name: "bcrypt wrong password", storedHash: "bcrypt$" + string(bcryptRaw), password: "wrong", want: false},
		{name: "sha256 legacy ok", storedHash: shaHash, password: password, want: true},
		{name: "sha256 legacy wrong password", storedHash: shaHash, password: "wrong", want: false},
		{name: "empty hash", storedHash: "", password: password, want: false},
		{name: "plain prefix rejected", storedHash: "plain$" + password, password: password, want: false},
		{name: "unknown prefix rejected", storedHash: "md5$abc", password: password, want: false},
		{name: "malformed sha256 rejected", storedHash: "sha256$onlysalt", password: password, want: false},
		{name: "bad sha256 salt rejected", storedHash: "sha256$zz$00", password: password, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyPassword(tt.storedHash, tt.password); got != tt.want {
				t.Fatalf("VerifyPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}
