package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func routeTestRuntime() *Runtime {
	return &Runtime{routes: RoutingConfig{
		StaticBase: "/static", MonitorBase: "/monitor", MonitorAPIBase: "/api/monitor", LoginPath: "/login",
	}}
}

func routeTestEntry(pattern string) Route {
	return Route{Pattern: pattern, Methods: []string{http.MethodGet},
		Authenticate: func(http.ResponseWriter, *http.Request) bool { return true },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(pattern))
		}),
	}
}

func TestExtraRoutesAllowExactRootAndSubtree(t *testing.T) {
	for _, patterns := range [][]string{
		{"/example", "/example/"},
		{"/example/", "/example"},
		{"/example", "/example/private"},
	} {
		t.Run(patterns[0]+"+"+patterns[1], func(t *testing.T) {
			mux := http.NewServeMux()
			if err := attachRoutes(mux, routeTestRuntime(), []Route{routeTestEntry(patterns[0]), routeTestEntry(patterns[1])}); err != nil {
				t.Fatalf("nonoverlapping exact and subtree routes rejected: %v", err)
			}
			for _, pattern := range patterns {
				requestPath := pattern
				if pattern[len(pattern)-1] == '/' {
					requestPath += "child"
				}
				response := httptest.NewRecorder()
				mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://example.com"+requestPath, nil))
				if response.Code != http.StatusOK || response.Body.String() != pattern {
					t.Fatalf("%s: got %d %q; want exact handler %q", requestPath, response.Code, response.Body.String(), pattern)
				}
			}
		})
	}
}

func TestExtraRoutesRejectActualOverlaps(t *testing.T) {
	for _, patterns := range [][]string{
		{"/example", "/example"},
		{"/example/", "/example/private"},
		{"/example/private", "/example/"},
		{"/example/private/", "/example/private/nested"},
		{"/example/private/nested", "/example/private/"},
	} {
		t.Run(patterns[0]+"+"+patterns[1], func(t *testing.T) {
			mux := http.NewServeMux()
			if err := attachRoutes(mux, routeTestRuntime(), []Route{routeTestEntry(patterns[0]), routeTestEntry(patterns[1])}); err == nil {
				t.Fatal("duplicate or overlapping subtree route accepted")
			}
		})
	}
}

func TestExtraRoutesKeepStandardRouteBoundaries(t *testing.T) {
	for _, pattern := range []string{"/healthz", "/api/", "/monitor/private", "/static/"} {
		t.Run(pattern, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("standard")) })
			if err := attachRoutes(mux, routeTestRuntime(), []Route{routeTestEntry(pattern)}); err == nil {
				t.Fatal("extension shadowed a standard route")
			}
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://example.com/healthz", nil))
			if response.Code != http.StatusOK || response.Body.String() != "standard" {
				t.Fatal("rejected registration changed the standard handler")
			}
		})
	}
}
