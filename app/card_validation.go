package app

import (
	"fmt"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/core/monitor"
	"github.com/ishizakahiroshi/heartdesk/internal/authz"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
)

// ValidateCardConfiguration checks extension and configured card identities using
// the same registries as New, without initializing sessions, databases or jobs.
func ValidateCardConfiguration(ext Extensions, configuredIDs []string, aliases map[string]string) error {
	if err := monitor.ValidateExtensions(ext); err != nil {
		return err
	}
	if err := authz.ValidateCardAliases(aliases); err != nil {
		return err
	}
	if err := validateCardAliasTargets(aliases, ext); err != nil {
		return err
	}
	known := map[string]bool{}
	for _, id := range navmeta.AllCardIDs() {
		known[id] = true
	}
	for _, card := range ext.Cards {
		known[card.Meta.ID] = true
	}
	for alias := range aliases {
		known[strings.TrimSpace(alias)] = true
	}
	for _, id := range configuredIDs {
		if !known[id] {
			return fmt.Errorf("app: configured card is not registered: %q", id)
		}
	}
	return nil
}
