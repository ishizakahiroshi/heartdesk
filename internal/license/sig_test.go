package license

import (
	"crypto/hmac"
	"strings"
	"testing"
)

// TestComputeLicenseSigDeterministic は同一 (key, tenant, agent) で同一署名になることを確認する。
func TestComputeLicenseSigDeterministic(t *testing.T) {
	key := "vendor-secret"
	a := ComputeLicenseSig(key, "tenant-b", "tenant-b-vps-sakura")
	b := ComputeLicenseSig(key, "tenant-b", "tenant-b-vps-sakura")
	if a != b {
		t.Fatalf("ComputeLicenseSig not deterministic: %q != %q", a, b)
	}
	if a == "" {
		t.Fatal("ComputeLicenseSig returned empty")
	}
}

// TestLicenseKeyIssueVerifyGolden は「発行 → 検証」が通るゴールデンテスト。
// GenerateLicenseKey (vendor_console/exports.go) と Verify (verifier.go) は同じ
// ComputeLicenseSig を経由するため、ここで発行ロジックを再現し、verifierImpl.Verify が
// 受理することを確認する（C7-C2: hmac-sign-logic-quadruplicated）。
// vendorSecret はビルド注入の package 変数なので、テスト中だけ一時的に設定して復元する。
func TestLicenseKeyIssueVerifyGolden(t *testing.T) {
	orig := vendorSecret
	defer func() { vendorSecret = orig }()
	vendorSecret = "golden-vendor-secret"

	tenantID := "tenant-a"
	agentID := "tenant-a-vps-host-1"

	// 発行（GenerateLicenseKey 相当）: <tenant>.<agent>.<sig>
	sig := ComputeLicenseSig(vendorSecret, tenantID, agentID)
	licenseKey := tenantID + "." + agentID + "." + sig

	// 検証（verifierImpl.Verify）が通ること。
	v := newVerifier()
	if err := v.Verify(agentID, licenseKey); err != nil {
		t.Fatalf("issue->verify golden failed: %v (key=%s)", err, licenseKey)
	}

	// 署名が壊れたキーは弾かれること。
	bad := tenantID + "." + agentID + "." + strings.Repeat("0", len(sig))
	if err := v.Verify(agentID, bad); err == nil {
		t.Fatal("Verify accepted a key with invalid signature (must reject)")
	}

	// ComputeVendorLicenseSig も同じ値を返すこと（鍵 = vendorSecret 経由の一致確認）。
	got, ok := ComputeVendorLicenseSig(tenantID, agentID)
	if !ok {
		t.Fatal("ComputeVendorLicenseSig returned ok=false despite vendorSecret set")
	}
	if !hmac.Equal([]byte(got), []byte(sig)) {
		t.Fatalf("ComputeVendorLicenseSig %q != ComputeLicenseSig %q", got, sig)
	}
}
