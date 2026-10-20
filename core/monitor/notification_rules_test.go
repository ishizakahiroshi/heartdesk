package monitor

import "testing"

func TestAlertRuleDefsIncludesNCUserRules(t *testing.T) {
	cases := []struct {
		ruleID string
	}{
		{"nc_user_created"},
		{"nc_user_first_login"},
	}

	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) {
			def, ok := AlertRuleDefs[tc.ruleID]
			if !ok {
				t.Fatalf("AlertRuleDefs[%q] not found", tc.ruleID)
			}
			if def.HasThreshold || def.HasRecovery || def.HasSustain {
				t.Fatalf("AlertRuleDefs[%q] = %+v, want all Has* false (no threshold concept)", tc.ruleID, def)
			}
			if def.Label == "" {
				t.Fatalf("AlertRuleDefs[%q].Label is empty", tc.ruleID)
			}

			found := false
			for _, id := range AlertRuleDefOrder {
				if id == tc.ruleID {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("AlertRuleDefOrder does not contain %q: %v", tc.ruleID, AlertRuleDefOrder)
			}
		})
	}
}
