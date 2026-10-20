package routing

import "testing"

func TestTenantConfigPublicHost(t *testing.T) {
	cases := []struct {
		name string
		tc   TenantConfig
		want string
	}{
		{"subdomain joins slug and base", TenantConfig{TenantSlug: "drive", RoutingMode: "subdomain", BaseHost: "example.com"}, "drive.example.com"},
		{"subdomain is case-insensitive and trimmed", TenantConfig{TenantSlug: " Drive ", RoutingMode: "SubDomain", BaseHost: " Example.COM "}, "drive.example.com"},
		{"path uses base as is", TenantConfig{TenantSlug: "heartdesk", RoutingMode: "path", BaseHost: "nc.example.net"}, "nc.example.net"},
		{"subdomain without slug", TenantConfig{RoutingMode: "subdomain", BaseHost: "example.com"}, ""},
		{"empty base", TenantConfig{TenantSlug: "drive", RoutingMode: "subdomain"}, ""},
	}
	for _, c := range cases {
		if got := c.tc.PublicHost(); got != c.want {
			t.Errorf("%s: PublicHost() = %q, want %q", c.name, got, c.want)
		}
	}
}
