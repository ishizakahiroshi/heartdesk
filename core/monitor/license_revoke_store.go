package monitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

type revokedEntry struct {
	AgentID   string `json:"agent_id,omitempty"`
	RevokedAt string `json:"revoked_at"`
	Reason    string `json:"reason,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func licenseRevokeStorePath() string {
	return heartdesk.Path("data/license/revoked_jti.json")
}

// RestoreLicenseRevokeStore は起動時に失効JTIストアをロードする。
func RestoreLicenseRevokeStore() {
	if err := loadRevokedJTIStore(); err != nil {
		log.Printf("ERROR: license_api: revoke store load failed: %v", err)
	}
}

func loadRevokedJTIStore() error {
	path := licenseRevokeStorePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			jtiMu.Lock()
			revokedJTIs = map[string]revokedEntry{}
			jtiMu.Unlock()
			return nil
		}
		return fmt.Errorf("read revoke store: %w", err)
	}

	store := map[string]revokedEntry{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &store); err != nil {
			return fmt.Errorf("parse revoke store: %w", err)
		}
	}

	jtiMu.Lock()
	revokedJTIs = store
	changed := cleanupExpiredRevokedJTIsLocked(time.Now())
	if changed {
		if err := persistRevokedJTIStoreLocked(); err != nil {
			jtiMu.Unlock()
			return err
		}
	}
	jtiMu.Unlock()
	return nil
}

func persistRevokedJTIStoreLocked() error {
	if revokedJTIs == nil {
		revokedJTIs = map[string]revokedEntry{}
	}
	cleanupExpiredRevokedJTIsLocked(time.Now())

	path := licenseRevokeStorePath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir revoke store dir: %w", err)
	}

	data, err := json.MarshalIndent(revokedJTIs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal revoke store: %w", err)
	}
	data = append(data, '\n')

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write revoke store tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename revoke store tmp: %w", err)
	}
	return nil
}

func cleanupExpiredRevokedJTIsLocked(now time.Time) bool {
	changed := false
	for jti, entry := range revokedJTIs {
		if revokedEntryExpired(entry, now) {
			delete(revokedJTIs, jti)
			changed = true
		}
	}
	return changed
}

func revokedEntryExpired(entry revokedEntry, now time.Time) bool {
	if entry.ExpiresAt == "" {
		return false
	}
	exp, err := time.Parse(time.RFC3339, entry.ExpiresAt)
	if err != nil {
		return false
	}
	return now.After(exp)
}
