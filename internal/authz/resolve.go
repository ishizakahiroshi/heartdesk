package authz

// ResolveInput は Resolve に渡す session 生成時の入力。
type ResolveInput struct {
	TenantID string
	// AgentID は session 生成時点では通常空。将来 agent 切替 UI を導入する場合に利用。
	AgentID string
	// Username は actions_user.toml / cards_user.toml のユーザー単位の追加制限に使う。
	Username string
	// AllCardIDs は計算対象のカードID一覧。
	AllCardIDs []string
	// SystemCardDefaults は config.toml [cards].defaults（カードID -> モード）。
	SystemCardDefaults map[string]string
	// SystemChildCardDefaults は config.toml [cards].child_defaults（親ID -> 子ID -> モード）。
	SystemChildCardDefaults map[string]map[string]string
	// SystemDefaultMode は config.toml [cards].default_mode。空なら "full"。
	SystemDefaultMode string
	// RoleDefaultActions は role 既定値（action ID -> true/false）。
	RoleDefaultActions map[string]bool
}

// Resolved は Resolve の結果。
type Resolved struct {
	CardModes         map[string]string
	ChildCardModes    map[string]map[string]string
	ActionPermissions map[string]bool
}

// Resolve は cards_tenants.toml / cards_user.toml / actions_tenants.toml / actions_user.toml を
// 読み込み、tenant -> agent -> user の順でマージした結果を返す。
// session 生成時に呼び出す用途。
func Resolve(in ResolveInput) Resolved {
	cardsTenants := CardsTenants()
	cardsUser := CardsUser()
	actionsTenants := ActionsTenants()
	actionsUser := ActionsUser()

	defaultMode := in.SystemDefaultMode
	if defaultMode == "" {
		defaultMode = cardsTenants.Defaults.DefaultMode
	}

	var tenantCards map[string]string
	var tenantChild map[string]map[string]string
	var agentCards map[string]string
	var agentChild map[string]map[string]string
	var tenantActions map[string]bool
	var agentActions map[string]bool

	if in.TenantID != "" {
		if te, ok := cardsTenants.Tenants[in.TenantID]; ok {
			tenantCards = te.Cards
			tenantChild = te.ChildCards
			if in.AgentID != "" {
				if ae, ok := te.Agents[in.AgentID]; ok {
					agentCards = ae.Cards
					agentChild = ae.ChildCards
				}
			}
		}
		if te, ok := actionsTenants.Tenants[in.TenantID]; ok {
			tenantActions = te.Actions
			if in.AgentID != "" {
				if ae, ok := te.Agents[in.AgentID]; ok {
					agentActions = ae.Actions
				}
			}
		}
	}

	var userHideCards []string
	var userHideChildCards map[string][]string
	var userDeny []string
	if in.Username != "" {
		if u, ok := cardsUser.Users[in.Username]; ok {
			userHideCards = u.HideCards
			userHideChildCards = u.HideChildCards
		}
		if u, ok := actionsUser.Users[in.Username]; ok {
			userDeny = u.Deny
		}
	}

	cardModes := MergeCards(MergeCardsInput{
		AllCardIDs:     in.AllCardIDs,
		SystemDefaults: in.SystemCardDefaults,
		DefaultMode:    defaultMode,
		TenantCards:    tenantCards,
		AgentCards:     agentCards,
		UserHideCards:  userHideCards,
	})

	childCardModes := MergeChildCards(MergeChildCardsInput{
		SystemDefaults:     in.SystemChildCardDefaults,
		TenantChildCards:   tenantChild,
		AgentChildCards:    agentChild,
		UserHideChildCards: userHideChildCards,
	})

	actions := MergeActions(MergeActionsInput{
		RoleDefaults:  in.RoleDefaultActions,
		TenantActions: tenantActions,
		AgentActions:  agentActions,
		UserDeny:      userDeny,
	})

	return Resolved{
		CardModes:         cardModes,
		ChildCardModes:    childCardModes,
		ActionPermissions: actions,
	}
}
