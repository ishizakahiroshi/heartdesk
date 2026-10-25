package license

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func TestDefaultIdentityPreservesStandaloneWire(t *testing.T) {
	got := CurrentIdentity()
	if got.OfflineFilenameExtension != ".hdlic" {
		t.Fatal("default offline filename extension changed")
	}
	if got.Issuer != "heartdesk-vendor" || got.Audience != "heartdesk-monitor" || got.OfflineAudience != "heartdesk-agent" || got.OfflineType != "heartdesk-offline-license" {
		t.Fatal("standalone identity changed")
	}
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	body, err := IssueOfflineLicense(priv, "synthetic", Claims{Subject: "alpha-vps-example"}, OfflineMeta{})
	if err != nil {
		t.Fatal(err)
	}
	var file OfflineFile
	if err := json.Unmarshal(body, &file); err != nil {
		t.Fatal(err)
	}
	if file.Header.Typ != "heartdesk-offline-license" {
		t.Fatal("default offline wire changed")
	}
}
