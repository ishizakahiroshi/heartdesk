package monitor

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func TestNcStorageReadsDirectGroupFolderResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocs/v1.php/cloud/users":
			_, _ = w.Write([]byte(`{"ocs":{"data":{"users":[]}}}`))
		case "/index.php/apps/groupfolders/folders":
			_, _ = w.Write([]byte(`{"7":{"id":7,"mount_point":"example","size":12345,"quota":-3}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := &config.AppConfig{}
	cfg.Nextcloud.URL, cfg.Nextcloud.AppUser, cfg.Nextcloud.AppPass = server.URL, "example", "example"
	cfg.NextcloudCache.StorageCacheTTL = 0
	got := GetNcStorage(cfg)
	if len(got.Errors) != 0 || got.GroupfolderTotals.Size != 12345 || len(got.Groupfolders) != 1 {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestNcStorageRejectsUnexpectedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"unexpected":"value"}`))
	}))
	defer server.Close()
	cfg := &config.AppConfig{}
	cfg.Nextcloud.URL, cfg.Nextcloud.AppUser = server.URL, "example"
	got := GetNcStorage(cfg)
	if got.Errors["users"] == "" || got.Errors["groupfolders"] == "" {
		t.Fatalf("missing response errors: %+v", got.Errors)
	}
}

func TestNcStorageDistinguishesZeroQuotaFromUnlimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocs/v1.php/cloud/users":
			_, _ = w.Write([]byte(`{"ocs":{"data":{"users":["zero","unlimited"]}}}`))
		case "/ocs/v1.php/cloud/users/zero":
			_, _ = w.Write([]byte(`{"ocs":{"data":{"quota":{"used":0,"quota":0}}}}`))
		case "/ocs/v1.php/cloud/users/unlimited":
			_, _ = w.Write([]byte(`{"ocs":{"data":{"quota":{"used":5,"quota":-3}}}}`))
		case "/index.php/apps/groupfolders/folders":
			_, _ = w.Write([]byte(`{"1":{"id":1,"size":0,"quota":0},"2":{"id":2,"size":5,"quota":-3}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := &config.AppConfig{}
	cfg.Nextcloud.URL, cfg.Nextcloud.AppUser = server.URL, "example"
	got := GetNcStorage(cfg)
	if len(got.Errors) != 0 || got.Users.Unlimited != 1 || got.GroupfolderTotals.Unlimited != 1 {
		t.Fatalf("unexpected quota totals: %+v", got)
	}
	for _, folder := range got.Groupfolders {
		if folder.ID == 1 && (folder.Quota == nil || *folder.Quota != 0) {
			t.Fatalf("zero quota was not preserved: %+v", folder)
		}
	}
}
