package monitor

import (
	"strings"
	"testing"
)

func TestSelfServiceRestartUsesConfiguredUnit(t *testing.T) {
	previous, runner := selfServiceName, restartSelf
	defer func() { ConfigureSelfServiceName(previous); restartSelf = runner }()
	if err := ValidateSelfServiceName("example_unit"); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "example;other", "../example", "example.service", "example unit"} {
		if ValidateSelfServiceName(invalid) == nil {
			t.Fatal("invalid unit accepted")
		}
	}
	ConfigureSelfServiceName("example_unit")
	var script string
	restartSelf = func(value string) error { script = value; return nil }
	RestartHeartdesk()
	if !strings.Contains(script, "systemctl restart example_unit") || strings.Contains(script, "restart heartdesk") {
		t.Fatalf("wrong restart target: %s", script)
	}
	if serviceNames[len(serviceNames)-1] != "example_unit" || procNames["example_unit"] != "bin/example_unit" {
		t.Fatal("service metadata retained old identity")
	}
}
