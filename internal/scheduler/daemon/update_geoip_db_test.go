package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func TestUpdateGeoIPDBDownloadsMMDB(t *testing.T) {
	origClient := geoIPDBHTTPClient
	geoIPDBHTTPClient = &http.Client{}
	t.Cleanup(func() {
		geoIPDBHTTPClient = origClient
	})

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "ipinfo_lite.mmdb")
	logPath := filepath.Join(tmpDir, "update-geoip-db.log")

	payload := make([]byte, minGeoIPDBSizeBytes+128)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("token"); got != "test-token" {
			t.Fatalf("unexpected token: %q", got)
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	t.Setenv("UPDATE_GEOIP_DB_LOG_PATH", logPath)
	cfg := &config.SchedulerConfig{
		GeoIPDBPath: dbPath,
		GeoIPToken:  "test-token",
		GeoIPDBURL:  srv.URL,
	}

	if err := UpdateGeoIPDB(context.Background(), cfg); err != nil {
		t.Fatalf("UpdateGeoIPDB failed: %v", err)
	}

	got, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("failed to read db: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("unexpected db size: got %d want %d", len(got), len(payload))
	}
}
