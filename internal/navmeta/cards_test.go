package navmeta

import (
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func TestIsCardVisibleWithoutAgent(t *testing.T) {
	if !IsCardVisible(CardSecServices, "", "monitor", nil) {
		t.Fatalf("card should be visible without agent context")
	}
}

func TestIsCardVisibleRentalDefaults(t *testing.T) {
	cfg := &config.AppConfig{
		Agents: map[string]config.AgentConfig{
			"r1": {
				AgentID:   "r1",
				AgentType: "rental",
			},
		},
	}

	if IsCardVisible(CardSecServices, "r1", "monitor", cfg) {
		t.Fatalf("sec-services must be hidden for rental default capabilities")
	}
	if !IsCardVisible(CardSecResources, "r1", "monitor", cfg) {
		t.Fatalf("sec-resources should be visible for rental default capabilities")
	}
	if !IsCardVisible(CardSecNginxLog, "r1", "monitor", cfg) {
		t.Fatalf("sec-nginx-log should be visible when rental has event.web_access")
	}
}

func TestIsCardVisibleExplicitCapabilitiesOverride(t *testing.T) {
	cfg := &config.AppConfig{
		Agents: map[string]config.AgentConfig{
			"r2": {
				AgentID:      "r2",
				AgentType:    "rental",
				Capabilities: []string{"snapshot.resources"},
			},
		},
	}

	if IsCardVisible(CardSecNginxLog, "r2", "monitor", cfg) {
		t.Fatalf("sec-nginx-log must be hidden when event.web_access is not declared")
	}
	if !IsCardVisible(CardSecResources, "r2", "monitor", cfg) {
		t.Fatalf("sec-resources should remain visible with explicit snapshot.resources")
	}
}

func TestIsCardVisibleUnknownAgentFallback(t *testing.T) {
	cfg := &config.AppConfig{
		Agents: map[string]config.AgentConfig{},
	}
	if !IsCardVisible(CardSecServices, "unknown-agent", "monitor", cfg) {
		t.Fatalf("unknown agent should keep backward-compatible visibility")
	}
}

// bindTestComponent はテスト中だけ、カードを [components] のコンポーネントに紐付ける。
// 汎用カードには既定の紐付けが無いため、テストで一時的に cardRequiredComponents へ登録する。
func bindTestComponent(t *testing.T, cardID, component string) {
	t.Helper()
	cardRequiredComponents[cardID] = component
	t.Cleanup(func() { delete(cardRequiredComponents, cardID) })
}

// TestIsCardVisibleComponentDisabled は
// 「[components] <name> = false で紐付くカードが消える」「true / 未設定なら元どおり」を確認する。
func TestIsCardVisibleComponentDisabled(t *testing.T) {
	bindTestComponent(t, CardSecSSL, "example_module")

	disabledCfg := &config.AppConfig{Components: map[string]bool{"example_module": false}}
	if IsCardVisible(CardSecSSL, "", "monitor", disabledCfg) {
		t.Fatalf("sec-ssl must be hidden when [components] example_module=false")
	}
	// コンポーネントに紐付かないカードは影響を受けない。
	if !IsCardVisible(CardSecServices, "", "monitor", disabledCfg) {
		t.Fatalf("cards without a required component must stay unaffected by example_module=false")
	}

	enabledCfg := &config.AppConfig{Components: map[string]bool{"example_module": true}}
	if !IsCardVisible(CardSecSSL, "", "monitor", enabledCfg) {
		t.Fatalf("sec-ssl should be visible when [components] example_module=true")
	}

	// 未設定（nil Components / nil cfg）は既定で有効。
	if !IsCardVisible(CardSecSSL, "", "monitor", &config.AppConfig{}) {
		t.Fatalf("sec-ssl should default to visible when Components is unset")
	}
	if !IsCardVisible(CardSecSSL, "", "monitor", nil) {
		t.Fatalf("sec-ssl should default to visible when cfg is nil")
	}
}

// TestCardComponentEnabled は CardComponentEnabled 単体の挙動（紐付け無しカードは常に true）を確認する。
func TestCardComponentEnabled(t *testing.T) {
	bindTestComponent(t, CardSecSSL, "example_module")

	cfg := &config.AppConfig{Components: map[string]bool{"example_module": false}}
	if CardComponentEnabled(CardSecSSL, cfg) {
		t.Fatalf("CardComponentEnabled must reflect the disabled example_module component")
	}
	if !CardComponentEnabled(CardSecServices, cfg) {
		t.Fatalf("CardComponentEnabled must default to true for cards with no required component")
	}
}

// TestRegistryCardsAreFullyDefined は、カードを外したあとにレジストリの定義が
// 欠けていないことの最低限の確認として、全カード ID が screen 定義と共有ラベルを持つことを確認する。
func TestRegistryCardsAreFullyDefined(t *testing.T) {
	for _, id := range AllCardIDs() {
		if _, ok := cardScreens[id]; !ok {
			t.Errorf("card %q has no cardScreens entry", id)
		}
		if _, ok := Label(id); !ok {
			t.Errorf("card %q has no shared label", id)
		}
	}
}
