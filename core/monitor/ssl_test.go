package monitor

import "testing"

func TestOpenSSLConnectAddressSupportsIPv6(t *testing.T) {
	got := sslConnectAddress("::1", "443")
	if got != "[::1]:443" {
		t.Fatalf("address = %q, want [::1]:443", got)
	}
}
