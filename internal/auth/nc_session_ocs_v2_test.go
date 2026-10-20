package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// OCS v2 の成功応答（statuscode 200）で、登録済みユーザーならログインできる。
// 100（v1 の成功コード）だけを成功とすると、ログイン済みでも弾かれてしまう。
func TestLoginNCAcceptsOCSv2Success(t *testing.T) {
	h := ncMessageTestHandler(t)
	swapNCMessageTestStore(t, map[string]User{
		"sso-user": {
			ID:            "sso-user",
			Username:      "sso-user",
			Role:          string(RoleTenantAdmin),
			AccessScreens: []string{string(ScreenMonitor)},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ocs":{"meta":{"status":"ok","statuscode":200,"message":"OK"},"data":{"id":"sso-user"}}}`))
	}))
	defer srv.Close()

	r := httptest.NewRequest(http.MethodGet, "/login/nc?next=/monitor", nil)
	r.Header.Set("Cookie", "oc_sessionPassphrase=abc")
	w := httptest.NewRecorder()
	h.loginNCWithBase(w, r, srv.URL)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (OCS v2 success must log in); body = %q", w.Code, http.StatusFound, w.Body.String())
	}
}

func TestOCSSucceeded(t *testing.T) {
	for code, want := range map[int]bool{200: true, 100: true, 997: false, 404: false, 0: false} {
		if got := ocsSucceeded(code); got != want {
			t.Errorf("ocsSucceeded(%d) = %v, want %v", code, got, want)
		}
	}
}
