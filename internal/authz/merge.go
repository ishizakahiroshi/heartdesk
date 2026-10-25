package authz

import "strings"

// CardMode はカード表示モード。"full" | "summary" | "hidden"
type CardMode string

const (
	CardModeFull    CardMode = "full"
	CardModeSummary CardMode = "summary"
	CardModeHidden  CardMode = "hidden"
)

// NormalizeCardMode は文字列を正規の CardMode に寄せる。該当しなければ空文字を返す。
func NormalizeCardMode(s string) CardMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "full":
		return CardModeFull
	case "summary":
		return CardModeSummary
	case "hidden":
		return CardModeHidden
	default:
		return ""
	}
}

// MergeCardsInput は MergeCards の入力。
// 各フィールドは nil でもよい（その層を適用しない扱い）。
type MergeCardsInput struct {
	// AllCardIDs: 計算対象のカードID一覧（システム側で定義された全カード）
	AllCardIDs []string
	// SystemDefaults: カードID -> モード（システム既定値。未指定カードは DefaultMode）
	SystemDefaults map[string]string
	// DefaultMode: SystemDefaults にも無いカードの既定。空なら "full"。
	DefaultMode string
	// TenantCards: cards_tenants.toml の [tenants.X.cards]
	TenantCards map[string]string
	// AgentCards: cards_tenants.toml の [tenants.X.agents.Y.cards]
	AgentCards map[string]string
	// UserHideCards: cards_user.toml の hide_cards（これらは常に hidden）
	UserHideCards []string
}

// MergeCards は tenant -> agent -> user の順でカード表示モードを評価し、
// カードID -> モード のマップを返す。
//
// ルール:
//  1. システム既定値
//  2. TenantCards で上書き
//  3. AgentCards で上書き
//  4. UserHideCards に含まれるカードは強制的に hidden
//
// user は復活不可（4 で hidden にするだけ）。
func MergeCards(in MergeCardsInput) map[string]string {
	defaultMode := in.DefaultMode
	if defaultMode == "" {
		defaultMode = string(CardModeFull)
	}

	result := make(map[string]string, len(in.AllCardIDs))
	for _, id := range in.AllCardIDs {
		mode := defaultMode
		if m, ok := in.SystemDefaults[id]; ok {
			if nm := NormalizeCardMode(m); nm != "" {
				mode = string(nm)
			}
		}
		if m, ok := in.TenantCards[id]; ok {
			if nm := NormalizeCardMode(m); nm != "" {
				mode = string(nm)
			}
		}
		if m, ok := in.AgentCards[id]; ok {
			if nm := NormalizeCardMode(m); nm != "" {
				mode = string(nm)
			}
		}
		result[id] = mode
	}

	for _, id := range in.UserHideCards {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		result[id] = string(CardModeHidden)
	}
	return result
}

// MergeChildCardsInput は MergeChildCards の入力。
type MergeChildCardsInput struct {
	// SystemDefaults / TenantChildCards / AgentChildCards:
	//   親カードID -> 子カードID -> モード
	SystemDefaults   map[string]map[string]string
	TenantChildCards map[string]map[string]string
	AgentChildCards  map[string]map[string]string
	// UserHideChildCards: 親カードID -> 子カードID の配列（hide only）
	UserHideChildCards map[string][]string
}

// MergeChildCards は子カード表示モードを tenant -> agent -> user 順でマージする。
// 親カードID -> 子カードID -> モード のマップを返す。
func MergeChildCards(in MergeChildCardsInput) map[string]map[string]string {
	parents := make(map[string]struct{})
	for p := range in.SystemDefaults {
		parents[p] = struct{}{}
	}
	for p := range in.TenantChildCards {
		parents[p] = struct{}{}
	}
	for p := range in.AgentChildCards {
		parents[p] = struct{}{}
	}
	for p := range in.UserHideChildCards {
		parents[p] = struct{}{}
	}
	if len(parents) == 0 {
		return nil
	}

	result := make(map[string]map[string]string, len(parents))
	for parent := range parents {
		children := make(map[string]string)
		if src, ok := in.SystemDefaults[parent]; ok {
			for k, v := range src {
				if nm := NormalizeCardMode(v); nm != "" {
					children[k] = string(nm)
				}
			}
		}
		if src, ok := in.TenantChildCards[parent]; ok {
			for k, v := range src {
				if nm := NormalizeCardMode(v); nm != "" {
					children[k] = string(nm)
				}
			}
		}
		if src, ok := in.AgentChildCards[parent]; ok {
			for k, v := range src {
				if nm := NormalizeCardMode(v); nm != "" {
					children[k] = string(nm)
				}
			}
		}
		for _, childID := range in.UserHideChildCards[parent] {
			childID = strings.TrimSpace(childID)
			if childID == "" {
				continue
			}
			children[childID] = string(CardModeHidden)
		}
		if len(children) > 0 {
			result[parent] = children
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// MergeActionsInput は MergeActions の入力。
type MergeActionsInput struct {
	// RoleDefaults: role 既定値（action ID -> allow(true)/deny(false)）
	RoleDefaults map[string]bool
	// TenantActions: actions_tenants.toml の [tenants.X.actions]
	TenantActions map[string]bool
	// AgentActions: actions_tenants.toml の [tenants.X.agents.Y.actions]
	AgentActions map[string]bool
	// UserDeny: actions_user.toml の deny（これらは常に false）
	UserDeny []string
}

// MergeActions は操作可否を tenant -> agent -> user 順でマージする。
// action ID -> allow(true)/deny(false) を返す。
//
// ルール:
//  1. RoleDefaults
//  2. TenantActions で上書き
//  3. AgentActions で上書き
//  4. UserDeny に含まれる action は強制的に false
//
// user は再許可不可（4 で false にするだけ）。
func MergeActions(in MergeActionsInput) map[string]bool {
	result := make(map[string]bool, len(in.RoleDefaults))
	for k, v := range CanonicalActionPolicy(in.RoleDefaults) {
		result[k] = v
	}
	for k, v := range CanonicalActionPolicy(in.TenantActions) {
		result[normalizeActionKey(k)] = v
	}
	for k, v := range CanonicalActionPolicy(in.AgentActions) {
		result[normalizeActionKey(k)] = v
	}
	for _, k := range in.UserDeny {
		key := normalizeActionKey(k)
		if key == "" {
			continue
		}
		result[key] = false
	}
	return result
}

func normalizeActionKey(s string) string {
	return CanonicalActionKey(s)
}
