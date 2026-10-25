package license

import (
	"crypto/ed25519"
	publiclicense "github.com/ishizakahiroshi/heartpost/agentlicense"
)

const OfflineFileVersion = publiclicense.OfflineFileVersion

type OfflineMeta = publiclicense.OfflineMeta
type OfflineFile = publiclicense.OfflineFile

func IssueOfflineLicense(priv ed25519.PrivateKey, kid string, claims Claims, meta OfflineMeta) ([]byte, error) {
	return publiclicense.IssueOfflineLicenseWithType(priv, kid, claims, meta, CurrentIdentity().OfflineType)
}
func ParseOfflineLicense(data []byte) (*OfflineFile, error) {
	return publiclicense.ParseOfflineLicense(data)
}
func VerifyOfflineFile(data []byte, resolver func(string) (ed25519.PublicKey, bool)) (*Claims, error) {
	return publiclicense.VerifyOfflineFile(data, resolver)
}
func LoadAndVerifyOfflineLicense(path string, resolver func(string) (ed25519.PublicKey, bool)) (*Claims, error) {
	return publiclicense.LoadAndVerifyOfflineLicense(path, resolver)
}
