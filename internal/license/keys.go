package license

import (
	"crypto/ed25519"
	publiclicense "github.com/ishizakahiroshi/heartpost/agentlicense"
)

// vendorPublicKeysB64 retains the existing -ldflags -X injection path.
var vendorPublicKeysB64 = ""

func ParseVendorPublicKeys() (map[string]ed25519.PublicKey, error) {
	return publiclicense.ParseVendorPublicKeys(signingMaterial().VendorPublicKeysB64)
}
func parseVendorPublicKeys(encoded string) (map[string]ed25519.PublicKey, error) {
	return publiclicense.ParseVendorPublicKeys(encoded)
}
func VendorPublicKeyResolver() (func(string) (ed25519.PublicKey, bool), error) {
	return publiclicense.VendorPublicKeyResolver(signingMaterial().VendorPublicKeysB64)
}
func ParsePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	return publiclicense.ParsePrivateKey(encoded)
}
func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	return publiclicense.ParsePublicKey(encoded)
}
