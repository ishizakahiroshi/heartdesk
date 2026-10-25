package license

import (
	"fmt"
	publiclicense "github.com/ishizakahiroshi/heartpost/agentlicense"
)

// vendorSecret retains the existing -ldflags -X injection path.
var vendorSecret = ""

func signingMaterial() publiclicense.Config {
	runtimeConfig.Lock()
	defer runtimeConfig.Unlock()
	return publiclicense.Config{VendorSecret: vendorSecret, VendorPublicKeysB64: vendorPublicKeysB64}
}

type verifierFacade struct {
	publiclicense.Verifier
	hasVendorSecret bool
}

func newVerifier() Verifier {
	material := signingMaterial()
	return &verifierFacade{Verifier: publiclicense.NewWithConfig(material), hasVendorSecret: material.VendorSecret != ""}
}

func (v *verifierFacade) Verify(agentID, licenseKey string) error {
	if !v.hasVendorSecret {
		return fmt.Errorf("license: vendorSecret not injected at build time; " + "rebuild with -ldflags \"-X github.com/ishizakahiroshi/heartdesk/internal/license.vendorSecret=<secret>\"")
	}
	return v.Verifier.Verify(agentID, licenseKey)
}

func ComputeLicenseSig(key, tenantID, agentID string) string {
	return publiclicense.ComputeLicenseSig(key, tenantID, agentID)
}
func ComputeVendorLicenseSig(tenantID, agentID string) (string, bool) {
	return publiclicense.ComputeVendorLicenseSig(signingMaterial().VendorSecret, tenantID, agentID)
}
