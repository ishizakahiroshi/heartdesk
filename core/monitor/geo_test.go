package monitor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// setGeoCfgForTest は geo.go の設定ホルダをテスト用に上書きし、
// クリーンアップで元に戻す。env 直読みは廃止したため env ではなくこのホルダを使う。
func setGeoCfgForTest(t *testing.T, s geoSettings) {
	t.Helper()
	geoCfgMu.Lock()
	orig := geoCfg
	geoCfg = s
	geoCfgMu.Unlock()
	t.Cleanup(func() {
		geoCfgMu.Lock()
		geoCfg = orig
		geoCfgMu.Unlock()
	})
}

func TestFetchIPInfoLite(t *testing.T) {
	origURL := geoIPBatchURL
	origClient := geoHTTPClient
	setGeoCfgForTest(t, geoSettings{Token: "test-token"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if got := r.URL.Query().Get("token"); got != "test-token" {
			t.Fatalf("unexpected token: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"1.1.1.1":{"ip":"1.1.1.1","country_code":"US"},
			"8.8.8.8":{"ip":"8.8.8.8","country_code":"JP"}
		}`))
	}))
	defer srv.Close()

	geoIPBatchURL = srv.URL
	geoHTTPClient = srv.Client()
	t.Cleanup(func() {
		geoIPBatchURL = origURL
		geoHTTPClient = origClient
	})

	result := fetchIPInfoLite([]string{"1.1.1.1", "8.8.8.8"})
	if got := result["1.1.1.1"]; got != "🇺🇸 アメリカ" {
		t.Fatalf("unexpected country for 1.1.1.1: %q", got)
	}
	if got := result["8.8.8.8"]; got != "🇯🇵 日本" {
		t.Fatalf("unexpected country for 8.8.8.8: %q", got)
	}
}

func TestGetCountryFlagsUsesCacheAndWritesMeta(t *testing.T) {
	origURL := geoIPBatchURL
	origClient := geoHTTPClient
	origCacheFile := geoCacheFile
	origMemCache := geoMemCache
	origMemMeta := geoMemMeta
	origLoadedAt := geoMemLoadedAt
	origLookupDB := geoLookupDB
	setGeoCfgForTest(t, geoSettings{Token: "cache-token", Mode: geoModeIPInfoAPI})

	tmpDir := t.TempDir()
	geoCacheFile = filepath.Join(tmpDir, "geo_cache.json")
	geoMemCache = nil
	geoMemMeta = geoCacheMeta{}
	geoMemLoadedAt = time.Time{}

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"8.8.8.8":{"ip":"8.8.8.8","country_code":"JP"}}`))
	}))
	defer srv.Close()

	geoIPBatchURL = srv.URL
	geoHTTPClient = srv.Client()
	geoLookupDB = func(ips []string) map[string]string { return nil }
	t.Cleanup(func() {
		geoIPBatchURL = origURL
		geoHTTPClient = origClient
		geoCacheFile = origCacheFile
		geoMemCache = origMemCache
		geoMemMeta = origMemMeta
		geoMemLoadedAt = origLoadedAt
		geoLookupDB = origLookupDB
	})

	first := GetCountryFlags([]string{"8.8.8.8"})
	if got := first["8.8.8.8"]; got != "🇯🇵 日本" {
		t.Fatalf("unexpected first result: %q", got)
	}
	second := GetCountryFlags([]string{"8.8.8.8"})
	if got := second["8.8.8.8"]; got != "🇯🇵 日本" {
		t.Fatalf("unexpected second result: %q", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly one API call, got %d", calls.Load())
	}

	raw, err := os.ReadFile(geoCacheFile)
	if err != nil {
		t.Fatalf("failed to read cache file: %v", err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("failed to decode cache file: %v", err)
	}
	metaRaw, ok := payload["_meta"]
	if !ok {
		t.Fatal("cache metadata missing")
	}
	var meta geoCacheMeta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatalf("failed to decode metadata: %v", err)
	}
	if meta.Provider != geoModeIPInfoAPI {
		t.Fatalf("unexpected provider: %q", meta.Provider)
	}
	if meta.TotalCalls != 1 {
		t.Fatalf("unexpected total calls: %d", meta.TotalCalls)
	}
	if meta.LastCallTS == 0 {
		t.Fatal("last_call_ts was not recorded")
	}
}

func TestGetCountryFlagsRespectsAPIMode(t *testing.T) {
	origURL := geoIPBatchURL
	origClient := geoHTTPClient
	origCacheFile := geoCacheFile
	origMemCache := geoMemCache
	origMemMeta := geoMemMeta
	origLoadedAt := geoMemLoadedAt
	origLookupDB := geoLookupDB
	setGeoCfgForTest(t, geoSettings{Token: "cache-token", Mode: geoModeIPInfoAPI})

	tmpDir := t.TempDir()
	geoCacheFile = filepath.Join(tmpDir, "geo_cache.json")
	geoMemCache = nil
	geoMemMeta = geoCacheMeta{}
	geoMemLoadedAt = time.Time{}

	var apiCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"1.1.1.1":{"ip":"1.1.1.1","country_code":"US"}}`))
	}))
	defer srv.Close()

	geoIPBatchURL = srv.URL
	geoHTTPClient = srv.Client()
	geoLookupDB = func(ips []string) map[string]string {
		return map[string]string{"1.1.1.1": "🇯🇵 日本"}
	}
	t.Cleanup(func() {
		geoIPBatchURL = origURL
		geoHTTPClient = origClient
		geoCacheFile = origCacheFile
		geoMemCache = origMemCache
		geoMemMeta = origMemMeta
		geoMemLoadedAt = origLoadedAt
		geoLookupDB = origLookupDB
	})

	got := GetCountryFlags([]string{"1.1.1.1"})
	if got["1.1.1.1"] != "🇺🇸 アメリカ" {
		t.Fatalf("unexpected API mode result: %q", got["1.1.1.1"])
	}
	if apiCalls.Load() != 1 {
		t.Fatalf("expected one API call, got %d", apiCalls.Load())
	}
}

func TestGetCountryFlagsRespectsDBMode(t *testing.T) {
	origURL := geoIPBatchURL
	origClient := geoHTTPClient
	origCacheFile := geoCacheFile
	origMemCache := geoMemCache
	origMemMeta := geoMemMeta
	origLoadedAt := geoMemLoadedAt
	origLookupDB := geoLookupDB
	setGeoCfgForTest(t, geoSettings{Token: "cache-token", Mode: geoModeIPInfoDB})

	tmpDir := t.TempDir()
	geoCacheFile = filepath.Join(tmpDir, "geo_cache.json")
	geoMemCache = nil
	geoMemMeta = geoCacheMeta{}
	geoMemLoadedAt = time.Time{}

	var apiCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"1.1.1.1":{"ip":"1.1.1.1","country_code":"US"}}`))
	}))
	defer srv.Close()

	geoIPBatchURL = srv.URL
	geoHTTPClient = srv.Client()
	geoLookupDB = func(ips []string) map[string]string {
		return map[string]string{"1.1.1.1": "🇯🇵 日本"}
	}
	t.Cleanup(func() {
		geoIPBatchURL = origURL
		geoHTTPClient = origClient
		geoCacheFile = origCacheFile
		geoMemCache = origMemCache
		geoMemMeta = origMemMeta
		geoMemLoadedAt = origLoadedAt
		geoLookupDB = origLookupDB
	})

	got := GetCountryFlags([]string{"1.1.1.1"})
	if got["1.1.1.1"] != "🇯🇵 日本" {
		t.Fatalf("unexpected DB mode result: %q", got["1.1.1.1"])
	}
	if apiCalls.Load() != 0 {
		t.Fatalf("expected zero API calls, got %d", apiCalls.Load())
	}
}

func TestGetCountryFlagsPrefersDBBeforeAPI(t *testing.T) {
	origURL := geoIPBatchURL
	origClient := geoHTTPClient
	origCacheFile := geoCacheFile
	origMemCache := geoMemCache
	origMemMeta := geoMemMeta
	origLoadedAt := geoMemLoadedAt
	origLookupDB := geoLookupDB
	setGeoCfgForTest(t, geoSettings{Token: "cache-token"})

	tmpDir := t.TempDir()
	geoCacheFile = filepath.Join(tmpDir, "geo_cache.json")
	geoMemCache = nil
	geoMemMeta = geoCacheMeta{}
	geoMemLoadedAt = time.Time{}

	var apiCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"8.8.8.8":{"ip":"8.8.8.8","country_code":"US"}}`))
	}))
	defer srv.Close()

	geoIPBatchURL = srv.URL
	geoHTTPClient = srv.Client()
	geoLookupDB = func(ips []string) map[string]string {
		return map[string]string{
			"1.1.1.1": "🇯🇵 日本",
		}
	}
	t.Cleanup(func() {
		geoIPBatchURL = origURL
		geoHTTPClient = origClient
		geoCacheFile = origCacheFile
		geoMemCache = origMemCache
		geoMemMeta = origMemMeta
		geoMemLoadedAt = origLoadedAt
		geoLookupDB = origLookupDB
	})

	got := GetCountryFlags([]string{"1.1.1.1", "8.8.8.8"})
	if got["1.1.1.1"] != "🇯🇵 日本" {
		t.Fatalf("unexpected DB result: %q", got["1.1.1.1"])
	}
	if got["8.8.8.8"] != "🇺🇸 アメリカ" {
		t.Fatalf("unexpected API result: %q", got["8.8.8.8"])
	}
	if apiCalls.Load() != 1 {
		t.Fatalf("expected one API call, got %d", apiCalls.Load())
	}
}
