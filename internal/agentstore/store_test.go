package agentstore

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestEventJSONL_AcceptsTenantAgentIDs(t *testing.T) {
	t.Setenv("SAB_BASE_DIR", t.TempDir())
	for _, id := range []string{"alpha-vps-host1", "t101-vps-host1", "tenant_b-rental-host-2", "alpha-host1"} {
		got := EventJSONL(id)
		if filepath.Base(got) != "events_"+id+".jsonl" {
			t.Errorf("EventJSONL(%q) = %q, want events_%s.jsonl", id, got, id)
		}
	}
}

func TestEventJSONL_RejectsInvalidAgentIDs(t *testing.T) {
	t.Setenv("SAB_BASE_DIR", t.TempDir())
	cases := []string{
		"",
		"alpha",
		"alpha-",
		"-vps-host1",
		"Alpha-vps-host1",
		"alpha-VPS-host1",
		"alpha-vps host1",
		"alpha-vps-../../escape",
		"alpha-vps-host1/../x",
	}
	for _, id := range cases {
		got := EventJSONL(id)
		if filepath.Base(got) != "events__invalid.jsonl" {
			t.Errorf("EventJSONL(%q) = %q, want events__invalid.jsonl", id, got)
		}
		if !strings.Contains(filepath.ToSlash(got), "data/logs/agents/") {
			t.Errorf("EventJSONL(%q) = %q escaped the agents directory", id, got)
		}
	}
}
