package monitor

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthzHandler_GET(t *testing.T) {
	// 認証情報（Cookie 等）を一切付けずに 200 になること。
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	HealthzHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"status":"ok"}` {
		t.Fatalf("body = %q, want {\"status\":\"ok\"}", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q, ログインへ飛ばしてはならない", loc)
	}
}

func TestHealthzHandler_HEAD(t *testing.T) {
	req := httptest.NewRequest(http.MethodHead, "/healthz", nil)
	rec := httptest.NewRecorder()
	HealthzHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD body = %q, want empty", rec.Body.String())
	}
}

func TestHealthzHandler_MethodNotAllowed(t *testing.T) {
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(m, "/healthz", nil)
		rec := httptest.NewRecorder()
		HealthzHandler(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: status = %d, want 405", m, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
			t.Fatalf("%s: Allow = %q, want \"GET, HEAD\"", m, allow)
		}
	}
}

// ミドルウェアなしで ServeMux に直接登録した形（main.go と同じ）でも 200 になること。
func TestHealthzHandler_ViaServeMux(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", HealthzHandler)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
