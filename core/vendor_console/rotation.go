package vendorconsole

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

// GenerateSigningKeyPair はed25519鍵ペアを生成してkid・公開鍵・秘密鍵のbase64を返す。
func GenerateSigningKeyPair() (kid, pubB64, privB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("key generation failed: %w", err)
	}

	// kid = "k" + タイムスタンプ8桁（秒）
	kid = fmt.Sprintf("k%d", time.Now().Unix()%100000000)
	pubB64 = base64.StdEncoding.EncodeToString(pub)
	privB64 = base64.StdEncoding.EncodeToString(priv)
	return kid, pubB64, privB64, nil
}
