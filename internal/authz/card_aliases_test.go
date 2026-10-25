package authz

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func withExampleCardAliases(t *testing.T) {
	t.Helper()
	cardAliasState.Lock()
	configured, aliases := cardAliasState.configured, cardAliasState.aliases
	cardAliasState.configured, cardAliasState.aliases = false, nil
	cardAliasState.Unlock()
	t.Cleanup(func() {
		cardAliasState.Lock()
		cardAliasState.configured, cardAliasState.aliases = configured, aliases
		cardAliasState.Unlock()
		ResetCardsCache()
	})
	input := map[string]string{"legacy-card": "current-card", "legacy-parent": "current-parent"}
	if err := ConfigureCardAliases(input); err != nil {
		t.Fatal(err)
	}
	input["legacy-card"] = "caller-mutation"
	if CanonicalCardID("legacy-card") != "current-card" {
		t.Fatal("configuration did not clone the caller's map")
	}
}

func TestCardAliasesImmutableAndValidated(t *testing.T) {
	withExampleCardAliases(t)
	for _, invalid := range []map[string]string{{"a": "a"}, {"a": "b", "b": "a"}, {"a": "b", "b": "c", "c": "a"}, {"a": "../b"}, {"a": "b", " a ": "c"}} {
		if ValidateCardAliases(invalid) == nil {
			t.Fatalf("invalid aliases accepted: %#v", invalid)
		}
	}
	flat, err := prepareCardAliases(map[string]string{"a": "b", "b": "c"})
	if err != nil || flat["a"] != "c" || flat["b"] != "c" {
		t.Fatalf("chain not flattened: %#v %v", flat, err)
	}
	copy := ConfiguredCardAliases()
	copy["legacy-card"] = "mutated"
	if CanonicalCardID(" legacy-card ") != "current-card" {
		t.Fatal("getter leaked mutable configuration")
	}
	if ConfigureCardAliases(nil) == nil {
		t.Fatal("startup identity was reconfigured")
	}
	input := map[string]string{"legacy-card": "hidden", "current-card": "full"}
	for i := 0; i < 30; i++ {
		out := CanonicalCardModes(input)
		if out["current-card"] != "hidden" || len(out) != 1 {
			t.Fatalf("same-layer deny lost: %#v", out)
		}
		out["current-card"] = "summary"
	}
	if input["legacy-card"] != "hidden" || input["current-card"] != "full" {
		t.Fatal("input policy was mutated")
	}
}

func TestCardAliasesKeepLayerPrecedence(t *testing.T) {
	withExampleCardAliases(t)
	for _, systemKey := range []string{"legacy-card", "current-card"} {
		for _, tenantKey := range []string{"legacy-card", "current-card"} {
			for _, agentKey := range []string{"legacy-card", "current-card"} {
				for _, first := range []string{"hidden", "full"} {
					last := "full"
					if first == "full" {
						last = "hidden"
					}
					in := MergeCardsInput{AllCardIDs: []string{"current-card"}, SystemDefaults: map[string]string{systemKey: first}, TenantCards: map[string]string{tenantKey: last}}
					if got := MergeCards(in)["current-card"]; got != last {
						t.Fatalf("tenant override %s -> %s got %s", first, last, got)
					}
					in.AgentCards = map[string]string{agentKey: first}
					if got := MergeCards(in)["current-card"]; got != first {
						t.Fatalf("agent override %s -> %s got %s", last, first, got)
					}
					for _, userKey := range []string{"legacy-card", "current-card"} {
						in.UserHideCards = []string{userKey}
						if got := MergeCards(in)["current-card"]; got != "hidden" {
							t.Fatalf("user hide %s got %s", userKey, got)
						}
					}
				}
			}
		}
	}
	for _, mode := range []string{"full", "summary", "hidden"} {
		if got := MergeCards(MergeCardsInput{AllCardIDs: []string{"current-card"}, SystemDefaults: map[string]string{"legacy-card": mode}})["current-card"]; got != mode {
			t.Fatalf("system defaults ignored: %s", got)
		}
	}
}

func TestCardAliasesChildLayersAndClones(t *testing.T) {
	withExampleCardAliases(t)
	system := map[string]map[string]string{"legacy-parent": {"legacy-card": "hidden"}, "current-parent": {"current-card": "full", "other": "summary"}}
	before := map[string]map[string]string{"legacy-parent": {"legacy-card": "hidden"}, "current-parent": {"current-card": "full", "other": "summary"}}
	if got := CanonicalChildCardModes(system)["current-parent"]["current-card"]; got != "hidden" {
		t.Fatal("same-layer child collision lost hidden")
	}
	for _, tenantParent := range []string{"legacy-parent", "current-parent"} {
		for _, tenantChild := range []string{"legacy-card", "current-card"} {
			in := MergeChildCardsInput{SystemDefaults: system, TenantChildCards: map[string]map[string]string{tenantParent: {tenantChild: "full"}}}
			if got := MergeChildCards(in)["current-parent"]["current-card"]; got != "full" {
				t.Fatal("tenant explicit full did not override prior hidden")
			}
			in.AgentChildCards = map[string]map[string]string{"legacy-parent": {"legacy-card": "summary"}}
			if got := MergeChildCards(in)["current-parent"]["current-card"]; got != "summary" {
				t.Fatal("agent explicit summary lost")
			}
			in.UserHideChildCards = map[string][]string{"legacy-parent": {"current-card"}, "current-parent": {"other"}}
			out := MergeChildCards(in)
			if out["current-parent"]["current-card"] != "hidden" || out["current-parent"]["other"] != "hidden" {
				t.Fatal("user child alias union lost a hide")
			}
		}
	}
	if !reflect.DeepEqual(system, before) {
		t.Fatal("nested input map mutated")
	}
}

func TestCardAliasesFileReadsDoNotRewriteAndExplicitWritesCanonical(t *testing.T) {
	withExampleCardAliases(t)
	root := t.TempDir()
	// The loader resolves environment dynamically; only a synthetic config root
	// is used, with no real configuration or database access.
	t.Setenv("HEARTDESK_BASE_DIR", root)
	t.Setenv("HEARTDESK_CONFIG_DIR", root)
	tenantRaw := "[tenants.alpha.cards]\nlegacy-card = 'hidden'\n[tenants.alpha.agents.example.cards]\nlegacy-card = 'summary'\n"
	userRaw := "[users.example]\nhide_cards = ['legacy-card']\n[users.example.hide_child_cards]\nlegacy-parent = ['legacy-card']\n"
	for name, data := range map[string]string{"cards_tenants.toml": tenantRaw, "cards_user.toml": userRaw} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := LoadCardsTenants()
	if err != nil || tenant.Tenants["alpha"].Cards["current-card"] != "hidden" || tenant.Tenants["alpha"].Agents["example"].Cards["current-card"] != "summary" {
		t.Fatalf("tenant read aliases: %#v %v", tenant, err)
	}
	user, err := LoadCardsUser()
	if err != nil || !reflect.DeepEqual(user.Users["example"].HideCards, []string{"current-card"}) {
		t.Fatalf("user read aliases: %#v %v", user, err)
	}
	for name, data := range map[string]string{"cards_tenants.toml": tenantRaw, "cards_user.toml": userRaw} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(got) != data {
			t.Fatal("read rewrote stored preferences")
		}
	}
	if err := SetUserHideCards("example", []string{"legacy-card"}, map[string][]string{"legacy-parent": {"legacy-card"}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "cards_user.toml"))
	if err != nil || strings.Contains(string(raw), "legacy-card") || strings.Contains(string(raw), "legacy-parent") || !strings.Contains(string(raw), "current-card") {
		t.Fatalf("explicit write not canonical: %v", err)
	}
}
