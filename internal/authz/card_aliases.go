package authz

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var cardAliasState struct {
	sync.RWMutex
	configured bool
	aliases    map[string]string
}

var cardIdentityName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

func prepareCardAliases(input map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(input))
	for raw, target := range input {
		key := strings.TrimSpace(raw)
		target = strings.TrimSpace(target)
		if !cardIdentityName.MatchString(key) || !cardIdentityName.MatchString(target) {
			return nil, fmt.Errorf("invalid card alias")
		}
		if previous, ok := out[key]; ok && previous != target {
			return nil, fmt.Errorf("duplicate card alias")
		}
		out[key] = target
	}
	resolved := make(map[string]string, len(out))
	for key := range out {
		seen := map[string]bool{key: true}
		target := out[key]
		for {
			if seen[target] {
				return nil, fmt.Errorf("cyclic card alias")
			}
			seen[target] = true
			next, ok := out[target]
			if !ok {
				break
			}
			target = next
		}
		resolved[key] = target
	}
	return resolved, nil
}

// ValidateCardAliases checks old-to-current card identities before startup state
// is consumed. Cycles and ambiguous normalized keys are rejected.
func ValidateCardAliases(input map[string]string) error {
	_, err := prepareCardAliases(input)
	return err
}

// ConfigureCardAliases fixes a private, flattened copy for this process. It does
// not rewrite any preference file. app.New calls it before sessions or caches.
func ConfigureCardAliases(input map[string]string) error {
	aliases, err := prepareCardAliases(input)
	if err != nil {
		return err
	}
	cardAliasState.Lock()
	defer cardAliasState.Unlock()
	if cardAliasState.configured {
		return fmt.Errorf("card aliases already fixed")
	}
	cardAliasState.aliases = aliases
	cardAliasState.configured = true
	return nil
}

// ConfiguredCardAliases returns a clone suitable for client preference reads.
func ConfiguredCardAliases() map[string]string {
	cardAliasState.RLock()
	defer cardAliasState.RUnlock()
	out := make(map[string]string, len(cardAliasState.aliases))
	for key, target := range cardAliasState.aliases {
		out[key] = target
	}
	return out
}

func CanonicalCardID(key string) string {
	key = strings.TrimSpace(key)
	cardAliasState.RLock()
	defer cardAliasState.RUnlock()
	if target, ok := cardAliasState.aliases[key]; ok {
		return target
	}
	return key
}

func restrictiveCardMode(a, b string) string {
	// This rule is only for colliding identities within ONE input layer. Normal
	// tenant/agent precedence still overrides the complete previous layer.
	if a == string(CardModeHidden) || b == string(CardModeHidden) {
		return string(CardModeHidden)
	}
	if a == string(CardModeSummary) || b == string(CardModeSummary) {
		return string(CardModeSummary)
	}
	return b
}

// CanonicalCardModes clones one policy layer. Same-layer aliases use
// hidden > summary > full, independently of map iteration order.
func CanonicalCardModes(input map[string]string) map[string]string {
	out := make(map[string]string, len(input))
	for raw, value := range input {
		key := CanonicalCardID(raw)
		mode := NormalizeCardMode(value)
		if key == "" || mode == "" {
			continue
		}
		if previous, ok := out[key]; ok {
			out[key] = restrictiveCardMode(previous, string(mode))
		} else {
			out[key] = string(mode)
		}
	}
	return out
}

// CanonicalChildCardModes clones one child-policy layer, including parent IDs.
func CanonicalChildCardModes(input map[string]map[string]string) map[string]map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]map[string]string, len(input))
	for raw, children := range input {
		parent := CanonicalCardID(raw)
		if parent == "" {
			continue
		}
		for child, mode := range CanonicalCardModes(children) {
			if out[parent] == nil {
				out[parent] = map[string]string{}
			}
			if previous, ok := out[parent][child]; ok {
				out[parent][child] = restrictiveCardMode(previous, mode)
			} else {
				out[parent][child] = mode
			}
		}
	}
	return out
}

func canonicalCardsTenants(doc CardsTenantsFile) CardsTenantsFile {
	for key, tenant := range doc.Tenants {
		tenant.Cards = CanonicalCardModes(tenant.Cards)
		tenant.ChildCards = CanonicalChildCardModes(tenant.ChildCards)
		for agentKey, agent := range tenant.Agents {
			agent.Cards = CanonicalCardModes(agent.Cards)
			agent.ChildCards = CanonicalChildCardModes(agent.ChildCards)
			tenant.Agents[agentKey] = agent
		}
		doc.Tenants[key] = tenant
	}
	return doc
}

func canonicalCardsUser(doc CardsUserFile) CardsUserFile {
	for key, user := range doc.Users {
		user.HideCards = normalizeIDList(user.HideCards)
		user.HideChildCards = normalizeHideChild(user.HideChildCards)
		doc.Users[key] = user
	}
	return doc
}
