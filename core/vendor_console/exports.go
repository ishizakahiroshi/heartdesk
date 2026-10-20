package vendorconsole

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/license"
)

// GenerateLicenseKey は HMAC ライセンスキーを生成して返す。
// vendorSec が未設定の場合は空文字を返す。署名計算は license.ComputeLicenseSig に
// 委譲し、license.Verify と同一ロジックを経由させる（C7-C2: hmac-sign-logic-quadruplicated）。
func GenerateLicenseKey(cfg *config.AppConfig, agentID, tenantID string) string {
	vendorSec := ""
	if cfg != nil {
		vendorSec = cfg.VendorLicense.LicenseKey
		if vendorSec == "" {
			vendorSec = cfg.AgentKeys[agentID]
		}
	}
	if vendorSec == "" {
		return ""
	}
	sig := license.ComputeLicenseSig(vendorSec, tenantID, agentID)
	return tenantID + "." + agentID + "." + sig
}

// IssueOfflineLicenseJWT はオフラインライセンス JWT を生成して返す。
// active_kid 未設定または signing key が見つからない場合は nil, nil を返す。
func IssueOfflineLicenseJWT(cfg *config.AppConfig, agentID string, expiryDays, graceDays, maxAgents int) ([]byte, error) {
	if cfg == nil {
		return nil, nil
	}
	activeKID := cfg.VendorLicense.ActiveKID
	if activeKID == "" {
		return nil, nil
	}
	keyEntry, ok := cfg.VendorLicense.SigningKeys[activeKID]
	if !ok || keyEntry.State != "active" {
		return nil, nil
	}
	privBytes, err := base64.StdEncoding.DecodeString(keyEntry.PrivateKeyB64)
	if err != nil {
		return nil, err
	}
	priv := ed25519.PrivateKey(privBytes)

	jti, err := license.NewJTI()
	if err != nil {
		return nil, err
	}

	tenantID := agentID
	if idx := strings.Index(agentID, "-"); idx > 0 {
		tenantID = agentID[:idx]
	}

	now := time.Now()
	exp := now.AddDate(0, 0, expiryDays)

	claims := license.Claims{
		Issuer:    "sab-vendor",
		Subject:   agentID,
		Audience:  "sab-agent",
		TenantID:  tenantID,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
		NotBefore: now.Unix(),
		JTI:       jti,
		Scope:     "agent.report",
		Type:      "offline",
	}

	meta := license.OfflineMeta{
		MaxAgents: maxAgents,
		GraceDays: graceDays,
		Features:  []string{"agent.report", "monitor.view"},
	}

	return license.IssueOfflineLicense(priv, activeKID, claims, meta)
}
