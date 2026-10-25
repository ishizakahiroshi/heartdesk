package app_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/app"
)

func TestCustomerOutputHelpers(t *testing.T) {
	for _, input := range []struct {
		raw  string
		want int
	}{{"0", 0}, {" 12 ", 12}, {"", 7}, {"-1", 7}, {"1x", 7}, {strings.Repeat("9", 100), 7}} {
		if got := app.ParseIntParam(input.raw, 7); got != input.want {
			t.Fatalf("ParseIntParam(%q)=%d want%d", input.raw, got, input.want)
		}
	}
	for _, input := range []struct{ raw, want string }{{"=1+1", "'=1+1"}, {"+1", "'+1"}, {"-1", "'-1"}, {"@example", "'@example"}, {"plain", "plain"}, {"", ""}, {" =1", " =1"}, {"\t=1", "\t=1"}, {"'already", "'already"}} {
		if got := app.CSVSafe(input.raw); got != input.want {
			t.Fatalf("CSVSafe(%q)=%q want%q", input.raw, got, input.want)
		}
	}
	w := httptest.NewRecorder()
	app.SetDownloadHeader(w, "例\"\\\r\n.csv", "text/csv; charset=utf-8")
	if got := w.Header().Get("Content-Disposition"); got != "attachment; filename=\"_____.csv\"; filename*=UTF-8''%E4%BE%8B%22%5C%0D%0A.csv" {
		t.Fatalf("download header=%q", got)
	}
	if w.Header().Get("Content-Type") != "text/csv; charset=utf-8" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("download headers changed")
	}
	w = httptest.NewRecorder()
	app.WriteActionError(w, "<example>&", http.StatusConflict)
	if w.Code != 409 || w.Body.String() != "{\"ok\":false,\"message\":\"\\u003cexample\\u003e\\u0026\"}\n" {
		t.Fatalf("action response=%d %q", w.Code, w.Body.String())
	}
	var response app.ActionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.OK || response.Message != "<example>&" {
		t.Fatalf("response alias mismatch: %v", err)
	}
	bom := app.CSVBOM()
	if !bytes.Equal(bom, []byte{0xef, 0xbb, 0xbf}) {
		t.Fatalf("BOM=%x", bom)
	}
	bom[0] = 0
	if !bytes.Equal(app.CSVBOM(), []byte{0xef, 0xbb, 0xbf}) {
		t.Fatal("caller mutated shared BOM")
	}
}

func TestRequireScreenRejectsUnknownBeforeCallback(t *testing.T) {
	for _, screen := range []string{"", "unknown", " monitor "} {
		called := false
		h := app.RequireScreen(screen)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://example.com/example", nil))
		if w.Code != 403 || called {
			t.Fatalf("screen%q: status%d callback%v", screen, w.Code, called)
		}
	}
}
