package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	publiclicense "github.com/ishizakahiroshi/heartpost/agentlicense"
	"os"
	"testing"
)

func TestFacadePreservesStandaloneGoldenWire(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	claims := Claims{Issuer: "heartdesk-vendor", Subject: "alpha-vps-example", Audience: "heartdesk-agent", TenantID: "alpha", IssuedAt: 100, ExpiresAt: 4102444800, JTI: "synthetic-golden", Scope: "agent.report", Type: "offline"}
	meta := OfflineMeta{TenantName: "Example", MaxAgents: 3, GraceDays: 7, Features: []string{"example"}}
	body, err := IssueOfflineLicense(priv, "synthetic", claims, meta)
	if err != nil {
		t.Fatal(err)
	}
	token, err := SignJWT(priv, "synthetic", claims)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(body)); got != "1e1ccd4180ca471512c9788897cac3df370a8776410120d7c76b68f6c5023903" {
		t.Fatal("standalone offline wire changed", got)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(token))); got != "2a268935e12afdba1153ece6c3aaf7d416c8fd21a85376bad66bb2e791dbfc26" {
		t.Fatal("standalone JWT wire changed", got)
	}
	if ErrTokenExpired != publiclicense.ErrTokenExpired || ErrSignatureInvalid != publiclicense.ErrSignatureInvalid || ErrUnknownKid != publiclicense.ErrUnknownKid {
		t.Fatal("token sentinels not shared")
	}
}

func TestFacadeLegacyLinkerMaterial(t *testing.T) {
	if os.Getenv("HEARTDESK_TEST_LINKER_FIXTURE") != "1" {
		t.Skip("explicit synthetic linker invocation")
	}
	agent := "alpha-vps-example"
	want := ComputeLicenseSig("synthetic-linker-material", "alpha", agent)
	got, ok := ComputeVendorLicenseSig("alpha", agent)
	if !ok || got != want {
		t.Fatal("legacy secret linker path ignored")
	}
	if err := New().Verify(agent, "alpha."+agent+"."+want); err != nil {
		t.Fatal(err)
	}
	keys, err := ParseVendorPublicKeys()
	if err != nil || len(keys) != 1 || len(keys["synthetic"]) != 32 {
		t.Fatal("legacy public-key linker path ignored")
	}
}
