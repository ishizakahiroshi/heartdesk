package monitor

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartpost/agentsig"
)

func signedAgentHeaders(agentID, key string, body []byte, ts int64) http.Header {
	tsStr := strconv.FormatInt(ts, 10)
	h := http.Header{}
	h.Set("X-Agent-Timestamp", tsStr)
	h.Set("X-Agent-Signature", agentsig.Compute(key, tsStr, body))
	return h
}

func TestVerifyAgentHMAC(t *testing.T) {
	body := []byte(`{"agent_id":"alpha-vps-host1","collectors":{}}`)
	now := time.Now().Unix()
	cfg := &config.AppConfig{
		AgentKeys:           map[string]string{"alpha-vps-host1": "local-secret"},
		AggregatorAgentKeys: map[string]string{"alpha-vps-host1": "aggregator-secret"},
	}
	cfg.AgentReport.TimestampSkewSec = 120

	tests := []struct {
		name    string
		header  http.Header
		agentID string
		wantErr bool
	}{
		{
			name:    "local key accepted",
			header:  signedAgentHeaders("alpha-vps-host1", "local-secret", body, now),
			agentID: "alpha-vps-host1",
		},
		{
			name:    "aggregator key accepted",
			header:  signedAgentHeaders("alpha-vps-host1", "aggregator-secret", body, now),
			agentID: "alpha-vps-host1",
		},
		{
			name:    "wrong key rejected",
			header:  signedAgentHeaders("alpha-vps-host1", "wrong-secret", body, now),
			agentID: "alpha-vps-host1",
			wantErr: true,
		},
		{
			name:    "unknown agent rejected",
			header:  signedAgentHeaders("alpha-vps-missing", "missing-secret", body, now),
			agentID: "alpha-vps-missing",
			wantErr: true,
		},
		{
			name:    "stale timestamp rejected",
			header:  signedAgentHeaders("alpha-vps-host1", "local-secret", body, now-600),
			agentID: "alpha-vps-host1",
			wantErr: true,
		},
		{
			name:    "missing headers rejected",
			header:  http.Header{},
			agentID: "alpha-vps-host1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyAgentHMAC(tt.header, body, tt.agentID, cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verifyAgentHMAC() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
