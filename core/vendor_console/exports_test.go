package vendorconsole

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/license"
)

func TestGenerateLicenseKeyUsesConfiguredSecret(t *testing.T) {
	var cfg config.AppConfig
	cfg.VendorLicense.LicenseKey = "vendor-secret"
	cfg.AgentKeys = map[string]string{"alpha-vps-host1": "agent-secret"}

	got := GenerateLicenseKey(&cfg, "alpha-vps-host1", "alpha")
	want := "alpha.alpha-vps-host1." + license.ComputeLicenseSig("vendor-secret", "alpha", "alpha-vps-host1")
	if got != want {
		t.Fatalf("GenerateLicenseKey() = %q, want %q", got, want)
	}
}

func TestGenerateLicenseKeyFallsBackToAgentSecret(t *testing.T) {
	var cfg config.AppConfig
	cfg.AgentKeys = map[string]string{"alpha-vps-host1": "agent-secret"}

	got := GenerateLicenseKey(&cfg, "alpha-vps-host1", "alpha")
	want := "alpha.alpha-vps-host1." + license.ComputeLicenseSig("agent-secret", "alpha", "alpha-vps-host1")
	if got != want {
		t.Fatalf("GenerateLicenseKey() = %q, want %q", got, want)
	}
	if got := GenerateLicenseKey(&cfg, "alpha-vps-missing", "alpha"); got != "" {
		t.Fatalf("GenerateLicenseKey() without matching key = %q, want empty", got)
	}
}

func TestIssueOfflineLicenseJWTActiveKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var cfg config.AppConfig
	cfg.VendorLicense.ActiveKID = "kid-1"
	cfg.VendorLicense.SigningKeys = map[string]config.SigningKeyEntry{
		"kid-1": {
			PrivateKeyB64: base64.StdEncoding.EncodeToString(priv),
			PublicKeyB64:  base64.StdEncoding.EncodeToString(pub),
			State:         "active",
		},
	}

	data, err := IssueOfflineLicenseJWT(&cfg, "alpha-vps-host1", 7, 3, 5)
	if err != nil {
		t.Fatalf("IssueOfflineLicenseJWT: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("IssueOfflineLicenseJWT returned empty data")
	}
	claims, err := license.VerifyOfflineFile(data, func(kid string) (ed25519.PublicKey, bool) {
		return pub, kid == "kid-1"
	})
	if err != nil {
		t.Fatalf("VerifyOfflineFile: %v", err)
	}
	if claims.Subject != "alpha-vps-host1" || claims.TenantID != "alpha" || claims.Type != "offline" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
}

func TestIssueOfflineLicenseJWTInactiveKeyReturnsNil(t *testing.T) {
	var cfg config.AppConfig
	if data, err := IssueOfflineLicenseJWT(&cfg, "alpha-vps-host1", 7, 3, 5); err != nil || data != nil {
		t.Fatalf("missing active_kid = (%q, %v), want nil, nil", data, err)
	}
	cfg.VendorLicense.ActiveKID = "kid-1"
	cfg.VendorLicense.SigningKeys = map[string]config.SigningKeyEntry{
		"kid-1": {State: "retired"},
	}
	if data, err := IssueOfflineLicenseJWT(&cfg, "alpha-vps-host1", 7, 3, 5); err != nil || data != nil {
		t.Fatalf("inactive signing key = (%q, %v), want nil, nil", data, err)
	}
}
