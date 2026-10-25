package license

import (
	"fmt"
	"regexp"
	"sync"
)

// Config supplies signing material and protocol identity for an embedded runtime.
// It is copied before request handlers start and never written to the environment.
type Config struct {
	VendorSecret             string
	VendorPublicKeysB64      string
	Issuer                   string
	Audience                 string
	OfflineAudience          string
	OfflineType              string
	OfflineFilenameExtension string
}

// Identity fixes application protocol names without changing cryptography or
// accepting tokens issued for another application. Empty Config fields retain
// the standalone application's historical wire identifiers.
type Identity struct{ Issuer, Audience, OfflineAudience, OfflineType, OfflineFilenameExtension string }

var identity = Identity{Issuer: "heartdesk-vendor", Audience: "heartdesk-monitor", OfflineAudience: "heartdesk-agent", OfflineType: "heartdesk-offline-license", OfflineFilenameExtension: ".hdlic"}

func CurrentIdentity() Identity {
	runtimeConfig.Lock()
	defer runtimeConfig.Unlock()
	return identity
}

var runtimeConfig struct {
	sync.Mutex
	configured bool
}

// Configure installs explicit runtime signing material once. Existing linker
// variables remain the default when the embedding application does not call it.
// Only app.New calls this, before constructing request handlers or workers.
func Configure(cfg Config) error {
	runtimeConfig.Lock()
	defer runtimeConfig.Unlock()
	if runtimeConfig.configured {
		return fmt.Errorf("license: runtime signing configuration is already fixed")
	}
	if _, err := parseVendorPublicKeys(cfg.VendorPublicKeysB64); err != nil {
		return fmt.Errorf("license: invalid runtime public keys: %w", err)
	}
	if cfg.OfflineFilenameExtension != "" && (!regexp.MustCompile(`^\.[A-Za-z0-9]+$`).MatchString(cfg.OfflineFilenameExtension) || len(cfg.OfflineFilenameExtension) > 32) {
		return fmt.Errorf("license: invalid offline filename extension")
	}
	vendorSecret = cfg.VendorSecret
	vendorPublicKeysB64 = cfg.VendorPublicKeysB64
	if cfg.Issuer != "" {
		identity.Issuer = cfg.Issuer
	}
	if cfg.Audience != "" {
		identity.Audience = cfg.Audience
	}
	if cfg.OfflineAudience != "" {
		identity.OfflineAudience = cfg.OfflineAudience
	}
	if cfg.OfflineType != "" {
		identity.OfflineType = cfg.OfflineType
	}
	if cfg.OfflineFilenameExtension != "" {
		identity.OfflineFilenameExtension = cfg.OfflineFilenameExtension
	}
	runtimeConfig.configured = true
	return nil
}
