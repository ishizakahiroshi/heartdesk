package app

import "testing"

func TestCloneConfigRetainsIsolatedServiceDefaults(t *testing.T) {
	input := &Config{NCFileAccessDefaultServiceAccounts: []string{"svc-app"}}
	first, err := cloneConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cloneConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.NCFileAccessDefaultServiceAccounts) != 1 || first.NCFileAccessDefaultServiceAccounts[0] != "svc-app" {
		t.Fatal("fallback lost through config clone")
	}
	input.NCFileAccessDefaultServiceAccounts[0] = "caller-change"
	first.NCFileAccessDefaultServiceAccounts[0] = "first-change"
	if second.NCFileAccessDefaultServiceAccounts[0] != "svc-app" {
		t.Fatal("config clones share fallback slice storage")
	}
	empty, err := cloneConfig(&Config{NCFileAccessDefaultServiceAccounts: []string{}})
	if err != nil || empty.NCFileAccessDefaultServiceAccounts == nil || len(empty.NCFileAccessDefaultServiceAccounts) != 0 {
		t.Fatal("explicit empty fallback changed")
	}
	generic, err := cloneConfig(&Config{})
	if err != nil || generic.NCFileAccessDefaultServiceAccounts != nil {
		t.Fatal("standalone fallback changed")
	}
}
