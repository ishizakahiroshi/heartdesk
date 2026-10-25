package heartdesk

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
)

// OperationalIdentityConfig preserves the names of an embedding application's
// existing locks, script metadata and trusted audit principal.
type OperationalIdentityConfig struct {
	SchedulerLockPrefix, AptUpdateLockPath, ScriptMetadataPrefix, AlertScriptName, TrustedAuditDBUser string
}

var operationalIdentity atomic.Pointer[OperationalIdentityConfig]
var operationalName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var metadataName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func resolvedOperationalIdentity(input *OperationalIdentityConfig) (OperationalIdentityConfig, error) {
	cfg := OperationalIdentityConfig{"heartdesk", "/var/lock/heartdesk-apt-update.lock", "HEARTDESK", "heartdesk-alerts", "heartdesk_app"}
	if input != nil {
		if input.SchedulerLockPrefix != "" {
			cfg.SchedulerLockPrefix = input.SchedulerLockPrefix
		}
		if input.AptUpdateLockPath != "" {
			cfg.AptUpdateLockPath = input.AptUpdateLockPath
		}
		if input.ScriptMetadataPrefix != "" {
			cfg.ScriptMetadataPrefix = input.ScriptMetadataPrefix
		}
		if input.AlertScriptName != "" {
			cfg.AlertScriptName = input.AlertScriptName
		}
		if input.TrustedAuditDBUser != "" {
			cfg.TrustedAuditDBUser = input.TrustedAuditDBUser
		}
	}
	for _, value := range []string{cfg.SchedulerLockPrefix, cfg.AlertScriptName, cfg.TrustedAuditDBUser} {
		if !operationalName.MatchString(value) || value == "." || value == ".." {
			return cfg, fmt.Errorf("invalid operational identity name")
		}
	}
	if !metadataName.MatchString(cfg.ScriptMetadataPrefix) || strings.ContainsAny(cfg.AptUpdateLockPath, "\x00\r\n") || !(filepath.IsAbs(cfg.AptUpdateLockPath) || path.IsAbs(cfg.AptUpdateLockPath)) {
		return cfg, fmt.Errorf("invalid operational identity path or metadata prefix")
	}
	return cfg, nil
}

func ValidateOperationalIdentity(input *OperationalIdentityConfig) error {
	_, err := resolvedOperationalIdentity(input)
	return err
}

func ConfigureOperationalIdentity(input *OperationalIdentityConfig) error {
	cfg, err := resolvedOperationalIdentity(input)
	if err != nil {
		return err
	}
	operationalIdentity.Store(&cfg)
	return nil
}

func OperationalIdentity() OperationalIdentityConfig {
	if cfg := operationalIdentity.Load(); cfg != nil {
		return *cfg
	}
	return OperationalIdentityConfig{"heartdesk", "/var/lock/heartdesk-apt-update.lock", "HEARTDESK", "heartdesk-alerts", "heartdesk_app"}
}
