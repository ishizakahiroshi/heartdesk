package authz

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var actionAliasState struct {
	sync.RWMutex
	configured bool
	aliases    map[string]string
}
var actionPermissionName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

func prepareActionPermissionAliases(input map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for raw, target := range input {
		key := strings.ToLower(strings.TrimSpace(raw))
		target = strings.ToLower(strings.TrimSpace(target))
		if !actionPermissionName.MatchString(key) || !actionPermissionName.MatchString(target) {
			return nil, fmt.Errorf("invalid action permission alias")
		}
		if previous, ok := out[key]; ok && previous != target {
			return nil, fmt.Errorf("duplicate action permission alias")
		}
		out[key] = target
	}
	for key := range out {
		seen := map[string]bool{key: true}
		target := out[key]
		for {
			if seen[target] {
				return nil, fmt.Errorf("cyclic action permission alias")
			}
			seen[target] = true
			next, ok := out[target]
			if !ok {
				break
			}
			target = next
		}
		out[key] = target
	}
	return out, nil
}

func ValidateActionPermissionAliases(input map[string]string) error {
	_, err := prepareActionPermissionAliases(input)
	return err
}

// ConfigureActionPermissionAliases is owned by app.New, before sessions or
// policy caches are used. Each source action uses the target's policy identity.
func ConfigureActionPermissionAliases(input map[string]string) error {
	aliases, err := prepareActionPermissionAliases(input)
	if err != nil {
		return err
	}
	actionAliasState.Lock()
	defer actionAliasState.Unlock()
	if actionAliasState.configured {
		return fmt.Errorf("action permission aliases already fixed")
	}
	actionAliasState.aliases = aliases
	actionAliasState.configured = true
	return nil
}

func CanonicalActionKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	actionAliasState.RLock()
	defer actionAliasState.RUnlock()
	if target, ok := actionAliasState.aliases[key]; ok {
		return target
	}
	return key
}

// CanonicalActionPolicy copies one policy layer. Conflicting names for the same
// permission retain an explicit deny, independently of map iteration order.
func CanonicalActionPolicy(input map[string]bool) map[string]bool {
	out := map[string]bool{}
	for key, allowed := range input {
		key = CanonicalActionKey(key)
		if previous, ok := out[key]; ok {
			out[key] = previous && allowed
		} else {
			out[key] = allowed
		}
	}
	return out
}

func ActionPolicyValue(policy map[string]bool, key string) (bool, bool) {
	value, ok := CanonicalActionPolicy(policy)[CanonicalActionKey(key)]
	return value, ok
}
