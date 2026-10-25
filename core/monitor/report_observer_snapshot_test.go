package monitor

import (
	"encoding/json"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func TestReportObserverCannotMutateSharedTenantConfiguration(t *testing.T) {
	previous := reportSavedHook
	t.Cleanup(func() { reportSavedHook = previous })
	strict := true
	cfg := &config.AppConfig{
		AgentKeys:           map[string]string{"alpha-web": "synthetic-local-key"},
		AggregatorAgentKeys: map[string]string{"alpha-web": "synthetic-aggregate-key"},
		AgentAllowedIPs:     map[string][]string{"alpha-web": {"203.0.113.10"}},
	}
	cfg.AgentReport.StrictLicense = &strict
	hits := 0
	reportSavedHook = func(received *config.AppConfig, report AgentReport) {
		hits++
		if received.AgentKeys["alpha-web"] != "synthetic-local-key" ||
			received.AggregatorAgentKeys["alpha-web"] != "synthetic-aggregate-key" ||
			received.AgentAllowedIPs["alpha-web"][0] != "203.0.113.10" ||
			!agentReportStrict(received) {
			t.Fatal("a previous hook changed the next report's configuration")
		}
		received.AgentKeys["alpha-web"] = "changed"
		received.AggregatorAgentKeys["alpha-web"] = "changed"
		received.AgentAllowedIPs["alpha-web"][0] = "198.51.100.20"
		*received.AgentReport.StrictLicense = false
	}
	AfterAgentReportSaved(cfg, AgentReport{AgentID: "alpha-web"})
	AfterAgentReportSaved(cfg, AgentReport{AgentID: "alpha-web"})
	if hits != 2 || cfg.AgentKeys["alpha-web"] != "synthetic-local-key" ||
		cfg.AggregatorAgentKeys["alpha-web"] != "synthetic-aggregate-key" ||
		cfg.AgentAllowedIPs["alpha-web"][0] != "203.0.113.10" || !strict {
		t.Fatal("hook mutated shared signing keys, IP restrictions or license mode")
	}
}

func TestReportObserverCannotMutateStoredCollectorPayload(t *testing.T) {
	previous := reportSavedHook
	t.Cleanup(func() { reportSavedHook = previous })
	report := AgentReport{AgentID: "alpha-web", Collectors: map[string]json.RawMessage{
		"example": json.RawMessage(`{"status":"ok"}`),
	}}
	hits := 0
	reportSavedHook = func(_ *config.AppConfig, received AgentReport) {
		hits++
		if string(received.Collectors["example"]) != `{"status":"ok"}` {
			t.Fatal("a previous hook changed a later observer's collector payload")
		}
		received.Collectors["example"][0] = '['
		delete(received.Collectors, "example")
	}
	AfterAgentReportSaved(&config.AppConfig{}, report)
	AfterAgentReportSaved(&config.AppConfig{}, report)
	if hits != 2 || string(report.Collectors["example"]) != `{"status":"ok"}` {
		t.Fatal("hook mutated the receiver's cached report map or raw payload")
	}
}
