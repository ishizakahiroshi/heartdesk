package license

import (
	"crypto/ed25519"
	publiclicense "github.com/ishizakahiroshi/heartpost/agentlicense"
)

type Claims = publiclicense.Claims

var (
	ErrTokenMalformed   = publiclicense.ErrTokenMalformed
	ErrTokenExpired     = publiclicense.ErrTokenExpired
	ErrTokenNotYetValid = publiclicense.ErrTokenNotYetValid
	ErrSignatureInvalid = publiclicense.ErrSignatureInvalid
	ErrUnknownKid       = publiclicense.ErrUnknownKid
)

func SignJWT(priv ed25519.PrivateKey, kid string, claims Claims) (string, error) {
	return publiclicense.SignJWT(priv, kid, claims)
}
func VerifyJWT(token string, resolver func(string) (ed25519.PublicKey, bool)) (*Claims, error) {
	return publiclicense.VerifyJWT(token, resolver)
}
func ExtractClaimsUnverified(token string) (*Claims, error) {
	return publiclicense.ExtractClaimsUnverified(token)
}
func ExtractKid(token string) (string, error) { return publiclicense.ExtractKid(token) }
func NewJTI() (string, error)                 { return publiclicense.NewJTI() }
