package license

import (
	"encoding/base64"
	"os"
	"os/exec"
	"testing"
)

func TestConfigureRuntimeOnce(t *testing.T) {
	if os.Getenv("HEARTDESK_TEST_LICENSE_CONFIG") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestConfigureRuntimeOnce$")
		cmd.Env = append(os.Environ(), "HEARTDESK_TEST_LICENSE_CONFIG=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
	before := vendorSecret
	if err := Configure(Config{VendorSecret: "invalid-must-not-install", VendorPublicKeysB64: "malformed"}); err == nil {
		t.Fatal("invalid public key accepted")
	}
	if vendorSecret != before {
		t.Fatal("validation failure installed signing material")
	}
	cfg := Config{VendorSecret: "synthetic-signing-material", VendorPublicKeysB64: "synthetic=" + base64.StdEncoding.EncodeToString(make([]byte, 32))}
	if err := Configure(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.VendorSecret = "caller mutation"
	if vendorSecret != "synthetic-signing-material" {
		t.Fatal("caller mutation changed configured material")
	}
	if err := Configure(Config{VendorSecret: "different-material"}); err == nil {
		t.Fatal("second instance replaced configured material")
	}
	if vendorSecret != "synthetic-signing-material" {
		t.Fatal("second configuration leaked into active verifier")
	}
}
