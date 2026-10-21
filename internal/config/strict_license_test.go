package config

import "testing"

// TestStrictLicenseDefault は strict_license の
// 「未設定時の既定は strict（true）」「明示 false は尊重」を確認する。
func TestStrictLicenseDefault(t *testing.T) {
	t.Run("unset defaults to true", func(t *testing.T) {
		cfg := &AppConfig{}
		cfg.applyDefaults()
		if cfg.AgentReport.StrictLicense == nil {
			t.Fatal("StrictLicense should be set by applyDefaults")
		}
		if !*cfg.AgentReport.StrictLicense {
			t.Fatal("StrictLicense default must be true")
		}
	})

	t.Run("explicit false is respected", func(t *testing.T) {
		cfg := &AppConfig{}
		f := false
		cfg.AgentReport.StrictLicense = &f
		cfg.applyDefaults()
		if cfg.AgentReport.StrictLicense == nil || *cfg.AgentReport.StrictLicense {
			t.Fatal("explicit StrictLicense=false must be preserved")
		}
	})
}
