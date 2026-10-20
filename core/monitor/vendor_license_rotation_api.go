package monitor

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

type vendorLicenseRotationResp struct {
	ActiveKID string                    `json:"active_kid"`
	Keys      []vendorSigningKeyDisplay `json:"keys"`
}

type vendorSigningKeyDisplay struct {
	KID         string `json:"kid"`
	State       string `json:"state"`
	Fingerprint string `json:"fingerprint"`
	RetiredAt   string `json:"retired_at"`
}

func GetVendorLicenseRotation(r *http.Request, appCfg *config.AppConfig) interface{} {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		return map[string]string{"error": "forbidden"}
	}
	if appCfg == nil {
		return vendorLicenseRotationResp{Keys: []vendorSigningKeyDisplay{}}
	}
	keys := make([]vendorSigningKeyDisplay, 0, len(appCfg.VendorLicense.SigningKeys))
	for kid, entry := range appCfg.VendorLicense.SigningKeys {
		fp := ""
		if entry.PublicKeyB64 != "" {
			if b, err := base64.StdEncoding.DecodeString(entry.PublicKeyB64); err == nil {
				sum := sha256.Sum256(b)
				fp = fmt.Sprintf("%x", sum[:6])
			}
		}
		keys = append(keys, vendorSigningKeyDisplay{
			KID:         kid,
			State:       entry.State,
			Fingerprint: fp,
			RetiredAt:   entry.RetiredAt,
		})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].KID < keys[j].KID })
	return vendorLicenseRotationResp{
		ActiveKID: appCfg.VendorLicense.ActiveKID,
		Keys:      keys,
	}
}
