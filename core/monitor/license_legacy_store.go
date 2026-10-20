package monitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
)

type legacyTokenStoreEntry struct {
	Token     string `json:"token"`
	AgentID   string `json:"agent_id"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

func legacyTokenStorePath() string {
	return sab.SabPath("data/license/legacy_tokens.json")
}

// RestoreLegacyTokenStore は起動時に legacy トークンストアをロードする。
func RestoreLegacyTokenStore() {
	if err := loadLegacyTokenStore(); err != nil {
		log.Printf("ERROR: license_api: legacy token store load failed: %v", err)
	}
}

func loadLegacyTokenStore() error {
	path := legacyTokenStorePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read legacy token store: %w", err)
	}

	store := map[string]legacyTokenStoreEntry{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &store); err != nil {
			return fmt.Errorf("parse legacy token store: %w", err)
		}
	}

	now := time.Now()
	legacyTokensMu.Lock()
	for agentID, e := range store {
		exp, err := time.Parse(time.RFC3339, e.ExpiresAt)
		if err != nil || now.After(exp) {
			continue // 期限切れエントリはスキップ
		}
		iat, _ := time.Parse(time.RFC3339, e.IssuedAt)
		legacyTokens[agentID] = &legacyTokenEntry{
			Token:     e.Token,
			AgentID:   e.AgentID,
			IssuedAt:  iat,
			ExpiresAt: exp,
		}
	}
	legacyTokensMu.Unlock()

	log.Printf("INFO: license_api: legacy token store loaded (%d entries)", len(store))
	return nil
}

// persistLegacyTokenStoreLocked は legacyTokensMu を保持したまま呼ぶこと。
func persistLegacyTokenStoreLocked() error {
	now := time.Now()
	store := make(map[string]legacyTokenStoreEntry, len(legacyTokens))
	for agentID, e := range legacyTokens {
		if e == nil || now.After(e.ExpiresAt) {
			continue // 期限切れは書かない
		}
		store[agentID] = legacyTokenStoreEntry{
			Token:     e.Token,
			AgentID:   e.AgentID,
			IssuedAt:  e.IssuedAt.UTC().Format(time.RFC3339),
			ExpiresAt: e.ExpiresAt.UTC().Format(time.RFC3339),
		}
	}

	path := legacyTokenStorePath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir legacy token store dir: %w", err)
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal legacy token store: %w", err)
	}
	data = append(data, '\n')

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write legacy token store tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename legacy token store tmp: %w", err)
	}
	return nil
}
