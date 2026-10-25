package license

import (
	"fmt"
	"sync"
)

// Config supplies signing material for an embedded runtime. It is copied before
// any receiver or license endpoint is started; it is never written to the env.
type Config struct {
	VendorSecret        string
	VendorPublicKeysB64 string
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
	vendorSecret = cfg.VendorSecret
	vendorPublicKeysB64 = cfg.VendorPublicKeysB64
	runtimeConfig.configured = true
	return nil
}
