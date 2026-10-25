package httpx_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/httpx"
	shared "github.com/ishizakahiroshi/heartdesk/internal/httpx"
)

func TestPublicHTTPClientSharesCanonicalTransports(t *testing.T) {
	if httpx.DefaultMaxBodyBytes != 10<<20 {
		t.Fatal("default body limit changed")
	}
	a, b := httpx.Client(time.Second, nil), shared.Client(2*time.Second, nil)
	if a.Transport != b.Transport || a.Timeout != time.Second || b.Timeout != 2*time.Second {
		t.Fatal("canonical default transport or timeout lost")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if httpx.Client(time.Second, tlsCfg).Transport != shared.Client(time.Second, tlsCfg).Transport || httpx.Client(time.Second, tlsCfg).Transport == httpx.Client(time.Second, tlsCfg.Clone()).Transport {
		t.Fatal("TLS pointer transport sharing changed")
	}
}

func TestPublicHTTPHelpersPreserveWireAndBounds(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/post":
			body, _ := io.ReadAll(r.Body)
			if r.Method != "POST" || string(body) != `{"example":"value"}` || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "Bearer override" || r.Header.Get("X-Example") != "yes" {
				t.Error("POST request contract changed")
			}
			w.WriteHeader(201)
			_, _ = w.Write([]byte("accepted"))
		case "/json":
			_, _ = w.Write([]byte(`{"example":1}`))
		case "/bad":
			w.WriteHeader(503)
			_, _ = w.Write([]byte("unavailable"))
		case "/do":
			if r.Method != "PATCH" {
				t.Error("Do method lost")
			}
			body, _ := io.ReadAll(r.Body)
			_, _ = w.Write(body)
		default:
			_, _ = w.Write([]byte("0123456789"))
		}
	}))
	defer server.Close()
	status, body, err := httpx.Get(context.Background(), server.URL, httpx.Options{MaxBodyBytes: 4})
	if err != nil || status != 200 || string(body) != "0123" {
		t.Fatalf("bounded GET=%d %q %v", status, body, err)
	}
	status, body, err = httpx.PostJSON(context.Background(), server.URL+"/post", map[string]string{"example": "value"}, httpx.Options{BearerToken: "synthetic", Headers: map[string]string{"Authorization": "Bearer override", "X-Example": "yes"}})
	if err != nil || status != 201 || string(body) != "accepted" {
		t.Fatalf("POST=%d %q %v", status, body, err)
	}
	status, body, err = httpx.Do(context.Background(), "PATCH", server.URL+"/do", strings.NewReader("example"), httpx.Options{})
	if err != nil || status != 200 || string(body) != "example" {
		t.Fatal("Do body contract changed")
	}
	var output map[string]int
	if err := httpx.GetJSON(context.Background(), server.URL+"/json", &output, httpx.Options{}); err != nil || output["example"] != 1 {
		t.Fatal("JSON decode lost")
	}
	if err := httpx.GetJSON(context.Background(), server.URL+"/bad", nil, httpx.Options{}); err == nil || err.Error() != "GET "+server.URL+"/bad: status 503: unavailable" {
		t.Fatalf("HTTP error=%v", err)
	}
	status, body, err = httpx.Get(context.Background(), server.URL+"/bad", httpx.Options{})
	if status != 503 || string(body) != "unavailable" || err != nil {
		t.Fatal("Get must return non2xx without transport error")
	}
	before := calls.Load()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := httpx.Get(ctx, server.URL, httpx.Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error=%v", err)
	}
	if calls.Load() != before {
		t.Fatal("canceled request reached server")
	}
	if _, _, err := httpx.PostJSON(context.Background(), server.URL, make(chan int), httpx.Options{}); err == nil {
		t.Fatal("JSON marshal failure lost")
	}
	if calls.Load() != before {
		t.Fatal("marshal failure reached server")
	}
}

func TestPublicHTTPClientUsesConfiguredTLSRoots(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("trusted")) }))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	config := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	status, body, err := httpx.Get(context.Background(), server.URL, httpx.Options{TLSConfig: config})
	if err != nil || status != 200 || string(body) != "trusted" {
		t.Fatalf("configured CA request=%d %q %v", status, body, err)
	}
}
