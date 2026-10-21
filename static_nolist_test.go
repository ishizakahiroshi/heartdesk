package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestStaticHandlerDoesNotListDirectories(t *testing.T) {
	content := fstest.MapFS{
		"js/app.js":    {Data: []byte("console.log('ok')")},
		"css/site.css": {Data: []byte("body{}")},
		"index.html":   {Data: []byte("<p>top</p>")},
	}
	h := http.StripPrefix("/static/", http.FileServer(noListFileSystem{http.FS(content)}))

	cases := []struct {
		path string
		want int
	}{
		{"/static/js/app.js", http.StatusOK},
		{"/static/css/site.css", http.StatusOK},
		{"/static/js/", http.StatusNotFound}, // ディレクトリの一覧は返さない
		{"/static/js", http.StatusNotFound},  // 末尾の / なしも同じ
		{"/static/", http.StatusNotFound},    // ルートも一覧にしない（index.html があっても）
		{"/static/missing.js", http.StatusNotFound},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		if rec.Code != c.want {
			t.Errorf("GET %s = %d, want %d", c.path, rec.Code, c.want)
		}
		if c.want == http.StatusNotFound && rec.Body.Len() > 0 {
			if body := rec.Body.String(); strings.Contains(body, "app.js") || strings.Contains(body, "site.css") {
				t.Errorf("GET %s: body leaks file names: %q", c.path, body)
			}
		}
	}
}
