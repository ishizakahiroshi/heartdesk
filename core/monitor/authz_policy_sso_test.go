package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

func TestTenantAdminCannotUseVendorOnlyUserManagementHandlers(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "create", handler: CreateUser},
		{name: "save policy", handler: SaveAuthzPolicy},
		{name: "delete", handler: DeleteUser},
		{name: "reset policy", handler: ResetAuthzPolicy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/monitor/authz", strings.NewReader(`{}`))
			ctx := context.WithValue(r.Context(), middleware.RoleKey, string(auth.RoleTenantAdmin))
			w := httptest.NewRecorder()

			tt.handler(w, r.WithContext(ctx))

			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
			}
			if !strings.Contains(w.Body.String(), "vendor_staff") {
				t.Fatalf("body = %q, want vendor_staff requirement", w.Body.String())
			}
		})
	}
}
