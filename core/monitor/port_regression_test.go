package monitor

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"testing"
)

func TestPortRecipientRuleOverridesSurviveRulesSave(t *testing.T) {
	cfg := newPersistConfig(t)
	raw := readRawRules(t, cfg)
	raw["recipients"] = json.RawMessage(`[{"id":"1","name":"Ops","email":"ops@example.com","enabled":true,"rules":{"memory_high":true,"disk_high":false}}]`)
	body, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.Alerts.RulesFile, body, 0600); err != nil {
		t.Fatal(err)
	}
	if ok, errs := SaveAlertRules(cfg, fullRulesPayload()); !ok {
		t.Fatalf("rules save: %v", errs)
	}
	saved := readSavedRules(t, cfg)
	want := map[string]bool{"memory_high": true, "disk_high": false}
	if len(saved.Recipients) != 1 || !reflect.DeepEqual(saved.Recipients[0].Rules, want) {
		t.Fatalf("recipient rule overrides lost: %+v", saved.Recipients)
	}
}

func TestPortRecipientRuleOverridesSurviveRecipientsSave(t *testing.T) {
	cfg := newPersistConfig(t)
	want := map[string]bool{"memory_high": true, "disk_high": false}
	recipients := []AlertRecipient{{Name: "Ops", Email: "ops@example.com", Enabled: true, Rules: want}}
	if ok, errs := SaveAlertRecipients(cfg, recipients); !ok {
		t.Fatalf("recipients save: %v", errs)
	}
	saved := readSavedRules(t, cfg)
	if len(saved.Recipients) != 1 || !reflect.DeepEqual(saved.Recipients[0].Rules, want) {
		t.Fatalf("recipient rule overrides lost: %+v", saved.Recipients)
	}
}

func TestPortRecipientsSaveRejectsMalformedExistingJSON(t *testing.T) {
	cfg := newPersistConfig(t)
	before := []byte(`{"rules": {broken`)
	if err := os.WriteFile(cfg.Alerts.RulesFile, before, 0600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := SaveAlertRecipients(cfg, []AlertRecipient{{Name: "Ops", Email: "ops@example.com", Enabled: true}}); ok {
		t.Fatal("malformed existing JSON must be rejected")
	}
	after, err := os.ReadFile(cfg.Alerts.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("rejected save changed original bytes: %q", after)
	}
}

func TestPortBulkBanRejectsWhitespaceWithoutExecution(t *testing.T) {
	fake := &fakeF2B{}
	fake.install(t)
	h := &Handler{}
	code, resp := postAction(t, h.actionBulkBan, bulkBanForm(" ", "\t", "\r\n"))
	if code != http.StatusBadRequest || resp.OK {
		t.Fatalf("empty targets: status=%d ok=%v", code, resp.OK)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.calls) != 0 {
		t.Fatalf("empty targets reached executor: %v", fake.calls)
	}
}
