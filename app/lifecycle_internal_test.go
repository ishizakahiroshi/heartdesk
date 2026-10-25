package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestCloseWaitsForActiveRequestBeforeClosingOwnedDB(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{}
	cfg.Database.DSN = filepath.Join(root, "shared.db")
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var rt *Runtime
	route := Route{Pattern: "/example/held", Authenticate: func(http.ResponseWriter, *http.Request) bool { return true }, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		if err := rt.ownedDB.Ping(); err != nil {
			t.Errorf("database closed while request alive: %v", err)
		}
		close(canceled)
		<-release
	})}
	var err error
	rt, err = New(Options{BaseDir: root, Config: cfg, VerifyLicense: func(*Config) error { return nil }, SkipStartupMaintenance: true, Routes: []Route{route}})
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		rt.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://example.com/example/held", nil))
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- rt.Close() }()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not cancel request context")
	}
	select {
	case err := <-closed:
		t.Fatal("Close returned before active request exited", err)
	default:
	}
	close(release)
	<-requestDone
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := rt.ownedDB.Ping(); err == nil {
		t.Fatal("Close left owned database open")
	}
}
