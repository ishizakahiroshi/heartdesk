package monitor

import (
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/alerts"
)

// TestNotifyRuleLabelsMatchCardDefs は 通知の見出しに出る件名が、
// 通知設定カードのラベルとズレていないことを見る。
//
// internal/alerts は core/monitor を参照できない（core/monitor →
// internal/scheduler/daemon → internal/alerts の循環になる）ため、
// alerts 側はラベルの写しを持っている。写しである以上ズレうるので、
// 参照できるこちら側で突き合わせる。
func TestNotifyRuleLabelsMatchCardDefs(t *testing.T) {
	notifyLabels := alerts.NotifyRuleLabels()

	for _, ruleID := range AlertRuleDefOrder {
		def, ok := AlertRuleDefs[ruleID]
		if !ok {
			t.Fatalf("AlertRuleDefOrder に定義の無い rule ID がある: %s", ruleID)
		}
		got, ok := notifyLabels[ruleID]
		if !ok {
			t.Errorf("通知側のラベル表に %s が無い（画面のラベル: %q）。"+
				"internal/alerts の ruleLabels へ足すこと", ruleID, def.Label)
			continue
		}
		if got != def.Label {
			t.Errorf("%s のラベルがズレている: 通知=%q 画面=%q", ruleID, got, def.Label)
		}
	}

	for ruleID := range notifyLabels {
		if _, ok := AlertRuleDefs[ruleID]; !ok {
			t.Errorf("画面に無い rule ID が通知側のラベル表に残っている: %s", ruleID)
		}
	}
}
