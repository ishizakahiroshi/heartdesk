package heartdesk

import "testing"

func TestOperationalIdentityCopiesAndValidates(t *testing.T) {
	t.Cleanup(func() { _ = ConfigureOperationalIdentity(nil) })
	input := &OperationalIdentityConfig{SchedulerLockPrefix: "example", AptUpdateLockPath: "/tmp/example.lock", ScriptMetadataPrefix: "EXAMPLE", AlertScriptName: "example-alerts", TrustedAuditDBUser: "example_app"}
	if err := ConfigureOperationalIdentity(input); err != nil {
		t.Fatal(err)
	}
	input.SchedulerLockPrefix = "mutated"
	if OperationalIdentity().SchedulerLockPrefix != "example" {
		t.Fatal("caller mutation retained")
	}
	for _, invalid := range []OperationalIdentityConfig{{SchedulerLockPrefix: "../escape"}, {AptUpdateLockPath: "relative.lock"}, {AptUpdateLockPath: "/tmp/example\ninvalid"}, {ScriptMetadataPrefix: "EXAMPLE;bad"}, {AlertScriptName: "../runner"}, {TrustedAuditDBUser: "user'"}} {
		if err := ConfigureOperationalIdentity(&invalid); err == nil {
			t.Fatalf("invalid identity accepted: %+v", invalid)
		}
		if OperationalIdentity().SchedulerLockPrefix != "example" {
			t.Fatal("invalid config changed active identity")
		}
	}
}
