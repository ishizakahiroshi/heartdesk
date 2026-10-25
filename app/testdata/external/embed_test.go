package embed_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/app"
)

type notifier struct{}

func (notifier) Prepare(*app.Config)                      {}
func (notifier) Notify(string, string) app.DeliveryResult { return app.DeliveryResult{} }

// This module has no imports from heartdesk/internal and builds both public
// monitor and scheduler entry points from the same configuration contract.
func TestExternalConsumer(t *testing.T) {
	cfg := &app.Config{}
	rt, err := app.New(app.Options{BaseDir: t.TempDir(), Config: cfg, VerifyLicense: func(*app.Config) error { return nil }, Notifiers: []app.Notifier{notifier{}}, SkipStartupMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if err := rt.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	rt.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://example.com/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rt.Run(ctx) == nil {
		t.Fatal("canceled monitor started")
	}
	if rt.RunScheduler(ctx) == nil {
		t.Fatal("canceled scheduler started")
	}
	_ = rt.Context(nil)
	_ = app.DefaultSessionManager()
	_ = app.DefaultStore()
	_ = app.ActionAllowed(nil, "vendor_staff", "example_action")
	_ = app.CanUseCard(app.Session{}, "sec-services")
}
