package monitor

import "testing"

func TestAgentEventDedupeKeySeparatesRequestIDs(t *testing.T) {
	base := map[string]interface{}{"method": "MKCOL", "status": float64(405), "path": "/nextcloud/x"}
	a := map[string]interface{}{"method": "MKCOL", "status": float64(405), "path": "/nextcloud/x", "request_id": "00000000000000000000000000000001"}
	b := map[string]interface{}{"method": "MKCOL", "status": float64(405), "path": "/nextcloud/x", "request_id": "00000000000000000000000000000002"}
	ts := "2026-10-30T10:00:00Z"
	if buildAgentEventDedupeKey("nginx", ts, a) == buildAgentEventDedupeKey("nginx", ts, b) {
		t.Fatal("events with different request ids must not dedupe into one")
	}
	if buildAgentEventDedupeKey("nginx", ts, a) == buildAgentEventDedupeKey("nginx", ts, base) {
		t.Fatal("request id must be part of the key")
	}
	// events without the new fields keep exactly the old key shape
	want := "nginx|" + ts + "||MKCOL||/nextcloud/x|||405||||"
	if got := buildAgentEventDedupeKey("nginx", ts, base); got != want {
		t.Fatalf("legacy key changed: %q", got)
	}
}

func TestReceiptCollectorIsIngestedAsOwnStream(t *testing.T) {
	kind, source := eventKindAndSource("integration_receipt", map[string]interface{}{})
	if kind != "integration_receipt" || source != "integration_receipt" {
		t.Fatalf("%q %q", kind, source)
	}
}

func TestIntegrationHTTPErrorRuleIsDefinedAndDefaultsOff(t *testing.T) {
	def, ok := AlertRuleDefs["integration_http_error"]
	if !ok {
		t.Fatal("missing public rule definition")
	}
	if def.HasSustain || def.DefaultThreshold != 1 || def.DefaultCooldownSec != 10800 {
		t.Fatalf("%+v", def)
	}
}
