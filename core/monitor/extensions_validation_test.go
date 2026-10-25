package monitor

import (
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
	"net/http"
	"testing"
)

func TestVendorPrefixDoesNotReserveExtensionNames(t *testing.T) {
	ext := Extensions{Cards: []CardExtension{{Meta: navmeta.MonitorCardMeta{ID: "sec-vendor-example", Key: "VENDOR_EXAMPLE", API: "vendor_example"}, Screens: []string{"vendor"}}}, APIs: []Endpoint{{Name: "vendor_example", CardID: "sec-vendor-example", Screen: "vendor", Handler: func(http.ResponseWriter, *http.Request, *RequestContext) {}}}}
	if err := ValidateExtensions(ext); err != nil {
		t.Fatal(err)
	}
	ext.APIs[0].Name = "vendor_licenses"
	if err := ValidateExtensions(ext); err == nil {
		t.Fatal("standard vendor API replaced")
	}
}
