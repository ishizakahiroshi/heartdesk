package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testJWTKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return pub, priv
}

func signTestJWT(t *testing.T, priv ed25519.PrivateKey, kid string, claims Claims) string {
	t.Helper()
	token, err := SignJWT(priv, kid, claims)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	return token
}

func TestSignVerifyJWT(t *testing.T) {
	pub, priv := testJWTKey(t)
	now := time.Now()
	claims := Claims{
		Issuer:    "heartdesk-vendor",
		Subject:   "tenant-b-vps-sakura",
		Audience:  "heartdesk-agent",
		TenantID:  "tenant-b",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		NotBefore: now.Add(-time.Minute).Unix(),
		JTI:       "jti-1",
		Scope:     "agent.report",
		Type:      "session",
	}
	token := signTestJWT(t, priv, "kid-1", claims)

	got, err := VerifyJWT(token, func(kid string) (ed25519.PublicKey, bool) {
		return pub, kid == "kid-1"
	})
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
	if got.Subject != claims.Subject || got.TenantID != claims.TenantID || got.JTI != claims.JTI {
		t.Fatalf("claims mismatch: %#v", got)
	}
}

func TestVerifyJWTErrorCases(t *testing.T) {
	pub, priv := testJWTKey(t)
	now := time.Now()
	baseClaims := Claims{
		Subject:   "tenant-b-vps-sakura",
		ExpiresAt: now.Add(time.Hour).Unix(),
		NotBefore: now.Add(-time.Minute).Unix(),
	}
	resolver := func(kid string) (ed25519.PublicKey, bool) {
		return pub, kid == "kid-1"
	}

	valid := signTestJWT(t, priv, "kid-1", baseClaims)
	expired := signTestJWT(t, priv, "kid-1", Claims{Subject: baseClaims.Subject, ExpiresAt: now.Add(-time.Hour).Unix()})
	notYet := signTestJWT(t, priv, "kid-1", Claims{Subject: baseClaims.Subject, ExpiresAt: now.Add(time.Hour).Unix(), NotBefore: now.Add(time.Hour).Unix()})
	unknownKid := signTestJWT(t, priv, "kid-missing", baseClaims)
	tamperedSig := tamperJWTSignature(t, valid)
	tamperedPayload := tamperJWTPayload(t, valid, func(claims Claims) Claims {
		claims.Subject = "attacker"
		return claims
	})
	badAlg := tamperJWTHeader(t, valid, jwtHeader{Alg: "none", Typ: "JWT", Kid: "kid-1"})

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{name: "malformed parts", token: "not-a-jwt", want: ErrTokenMalformed},
		{name: "bad alg", token: badAlg, want: ErrTokenMalformed},
		{name: "unknown kid", token: unknownKid, want: ErrUnknownKid},
		{name: "invalid signature bytes", token: tamperedSig, want: ErrSignatureInvalid},
		{name: "tampered payload", token: tamperedPayload, want: ErrSignatureInvalid},
		{name: "expired", token: expired, want: ErrTokenExpired},
		{name: "not yet valid", token: notYet, want: ErrTokenNotYetValid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyJWT(tt.token, resolver)
			if !errors.Is(err, tt.want) {
				t.Fatalf("VerifyJWT() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func tamperJWTHeader(t *testing.T, token string, hdr jwtHeader) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("bad token parts: %q", token)
	}
	raw, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}

// tamperJWTSignature は署名部をデコードして1バイト反転し、確実に「異なる署名」を作る。
// base64 末尾文字の置換は有効ビットが少なく約 1/4 の確率で同一バイトに復号されてフレーキーに
// なるため、デコード→バイト反転→再エンコードで決定的に改竄する。
func tamperJWTSignature(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("bad token parts: %q", token)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("empty signature")
	}
	sig[0] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}

func tamperJWTPayload(t *testing.T, token string, fn func(Claims) Claims) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("bad token parts: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims Claims
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	raw, err = json.Marshal(fn(claims))
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}
