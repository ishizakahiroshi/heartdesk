package monitor

import (
	"path/filepath"
	"testing"

	heartdesk "github.com/ishizakahiroshi/heartdesk/internal"
)

func TestConfiguredOperationalIdentityReadsExistingMetadataAndAuditUser(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	t.Cleanup(func() { _ = heartdesk.ConfigureOperationalIdentity(nil) })
	if err := heartdesk.ConfigureOperationalIdentity(&heartdesk.OperationalIdentityConfig{ScriptMetadataPrefix: "EXAMPLE", AlertScriptName: "example-alerts", TrustedAuditDBUser: "example_app"}); err != nil {
		t.Fatal(err)
	}
	metadata := extractScriptMeta([]string{"# EXAMPLE_LABEL=Existing task", "# EXAMPLE_SUMMARY=Existing summary", "# HEARTDESK_LABEL=Wrong namespace"})
	if metadata["LABEL"] != "Existing task" || metadata["SUMMARY"] != "Existing summary" {
		t.Fatal("existing script metadata was lost")
	}
	if scriptCheckAlerts() != filepath.Join(base, "bin", "example-alerts") || cronJobSpecsList()[0].label != "example-alerts" {
		t.Fatal("existing alert script identity changed")
	}
	trusted := map[string]bool{"198.51.100.9": true}
	record := auditLogRecord{User: "example_app", RemoteAddr: "198.51.100.9", Event: "Login attempt: synthetic"}
	if !auditAnomalyIsAppTrustedLogin(&record, trusted) {
		t.Fatal("configured trusted application login was not recognized")
	}
	record.User = "heartdesk_app"
	if auditAnomalyIsAppTrustedLogin(&record, trusted) {
		t.Fatal("another application was excluded as trusted")
	}
	record.User = "example_app"
	record.RemoteAddr = "198.51.100.10"
	if auditAnomalyIsAppTrustedLogin(&record, trusted) {
		t.Fatal("untrusted address was excluded")
	}
}
