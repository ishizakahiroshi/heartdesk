package authz

import "testing"

func TestMergeCardsLayeringAndUserHide(t *testing.T) {
	got := MergeCards(MergeCardsInput{
		AllCardIDs: []string{"overview", "license", "logs"},
		SystemDefaults: map[string]string{
			"overview": "summary",
			"license":  "full",
		},
		DefaultMode: "summary",
		TenantCards: map[string]string{
			"overview": "full",
			"logs":     "full",
		},
		AgentCards: map[string]string{
			"logs": "summary",
		},
		UserHideCards: []string{"overview", "missing"},
	})

	if got["overview"] != string(CardModeHidden) {
		t.Fatalf("user hide must be final for overview, got %q", got["overview"])
	}
	if got["license"] != string(CardModeFull) {
		t.Fatalf("system default for license = %q", got["license"])
	}
	if got["logs"] != string(CardModeSummary) {
		t.Fatalf("agent override for logs = %q", got["logs"])
	}
	if got["missing"] != string(CardModeHidden) {
		t.Fatalf("user hide for unknown card should still be represented, got %q", got["missing"])
	}
}

func TestMergeChildCardsUserHideAndEmpty(t *testing.T) {
	if got := MergeChildCards(MergeChildCardsInput{}); got != nil {
		t.Fatalf("empty input should return nil, got %#v", got)
	}

	got := MergeChildCards(MergeChildCardsInput{
		SystemDefaults: map[string]map[string]string{
			"parent": {"child": "full", "other": "summary"},
		},
		TenantChildCards: map[string]map[string]string{
			"parent": {"child": "summary"},
		},
		AgentChildCards: map[string]map[string]string{
			"parent": {"child": "full"},
		},
		UserHideChildCards: map[string][]string{
			"parent": {"child"},
		},
	})

	if got["parent"]["child"] != string(CardModeHidden) {
		t.Fatalf("user child hide must be final, got %q", got["parent"]["child"])
	}
	if got["parent"]["other"] != string(CardModeSummary) {
		t.Fatalf("system child default should remain, got %q", got["parent"]["other"])
	}
}

func TestMergeActionsUserDenyIsFinal(t *testing.T) {
	got := MergeActions(MergeActionsInput{
		RoleDefaults:  map[string]bool{"reboot": true, "backup": false},
		TenantActions: map[string]bool{"backup": true},
		AgentActions:  map[string]bool{"reboot": true},
		UserDeny:      []string{" REBOOT "},
	})

	if got["reboot"] {
		t.Fatal("user deny must force reboot=false")
	}
	if !got["backup"] {
		t.Fatal("tenant allow for backup should remain true")
	}
}

func TestNormalizeCardMode(t *testing.T) {
	tests := map[string]CardMode{
		" FULL ":  CardModeFull,
		"summary": CardModeSummary,
		"hidden":  CardModeHidden,
		"bad":     "",
		"":        "",
	}
	for in, want := range tests {
		if got := NormalizeCardMode(in); got != want {
			t.Fatalf("NormalizeCardMode(%q) = %q, want %q", in, got, want)
		}
	}
}
