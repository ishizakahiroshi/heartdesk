package auth

import (
	"fmt"
	"path"
	"strings"
	"sync"
	"unicode"
)

// IdentityConfig supplies application identity without changing authentication
// policy. Empty fields retain the standard identity. app.New fixes it once.
type IdentityConfig struct {
	LoginTitle                    string
	LoginSubtitle                 string
	NextcloudSessionEntryPath     string
	LoginChallengeCookieName      string
	TOTPIssuer                    string
	NextcloudNotRegisteredMessage string
}

var identityState struct {
	sync.RWMutex
	configured bool
	value      IdentityConfig
}

func resolvedIdentity(value IdentityConfig) IdentityConfig {
	if value.LoginTitle == "" {
		value.LoginTitle = "heartdesk"
	}
	if value.LoginSubtitle == "" {
		value.LoginSubtitle = "server dashboard"
	}
	if value.NextcloudSessionEntryPath == "" {
		value.NextcloudSessionEntryPath = ncSessionEntryPath
	}
	if value.LoginChallengeCookieName == "" {
		value.LoginChallengeCookieName = loginChallengeCookie
	}
	value.TOTPIssuer = strings.TrimSpace(value.TOTPIssuer)
	if value.TOTPIssuer == "" {
		value.TOTPIssuer = "heartdesk"
	}
	if value.NextcloudNotRegisteredMessage == "" {
		value.NextcloudNotRegisteredMessage = ncNotRegisteredError
	}
	return value
}

// ValidateIdentity rejects external, ambiguous or header-unsafe entry paths and
// invalid cookie token names before any process-scoped configuration changes.
func ValidateIdentity(value IdentityConfig) error {
	value = resolvedIdentity(value)
	entry := value.NextcloudSessionEntryPath
	if !strings.HasPrefix(entry, "/") || strings.HasPrefix(entry, "//") || strings.ContainsAny(entry, "?#\\%") || path.Clean(entry) != entry {
		return fmt.Errorf("auth: invalid Nextcloud session entry path")
	}
	for _, r := range entry {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("auth: invalid Nextcloud session entry path")
		}
	}
	for _, r := range value.LoginChallengeCookieName {
		if r <= 0x20 || r >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r) {
			return fmt.Errorf("auth: invalid login challenge cookie name")
		}
	}
	return nil
}

// ConfigureIdentity is a startup-only operation owned by app.New. The copied
// string-only value cannot be changed by mutating the caller's options later.
func ConfigureIdentity(value IdentityConfig) error {
	if err := ValidateIdentity(value); err != nil {
		return err
	}
	identityState.Lock()
	defer identityState.Unlock()
	if identityState.configured {
		return fmt.Errorf("auth: identity already configured")
	}
	identityState.value = resolvedIdentity(value)
	identityState.configured = true
	return nil
}

func CurrentIdentity() IdentityConfig {
	identityState.RLock()
	defer identityState.RUnlock()
	if !identityState.configured {
		return resolvedIdentity(IdentityConfig{})
	}
	return identityState.value
}
