package auth

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
	"github.com/ishizakahiroshi/heartdesk/web"
)

func useTestIdentity(t *testing.T, value IdentityConfig) {
	t.Helper()
	identityState.Lock()
	previous, configured := identityState.value, identityState.configured
	identityState.configured = false
	identityState.Unlock()
	t.Cleanup(func() {
		identityState.Lock()
		identityState.value, identityState.configured = previous, configured
		identityState.Unlock()
	})
	if err := ConfigureIdentity(value); err != nil {
		t.Fatal(err)
	}
}

func TestAuthIdentityDefaultsAndValidation(t *testing.T) {
	value := resolvedIdentity(IdentityConfig{})
	if value.LoginTitle != "heartdesk" || value.LoginSubtitle != "server dashboard" || value.NextcloudSessionEntryPath != ncSessionEntryPath || value.LoginChallengeCookieName != loginChallengeCookie || value.TOTPIssuer != "heartdesk" || value.NextcloudNotRegisteredMessage != ncNotRegisteredError {
		t.Fatal("standard authentication identity changed")
	}
	for _, entry := range []string{"relative", "https://example.com/login", "//example.com/login", "/entry?x=1", "/entry#fragment", "/entry\r\nInjected", "/entry\t", "/entry path", "/entry\\other", "/entry/%2fother", "/entry/../other"} {
		if err := ValidateIdentity(IdentityConfig{NextcloudSessionEntryPath: entry}); err == nil {
			t.Errorf("unsafe entry accepted: %q", entry)
		}
	}
	for _, name := range []string{"two names", "name=value", "name;other", "name\r\nOther", "名前", "name/path"} {
		if err := ValidateIdentity(IdentityConfig{LoginChallengeCookieName: name}); err == nil {
			t.Errorf("invalid cookie name accepted: %q", name)
		}
	}
	if err := ValidateIdentity(IdentityConfig{NextcloudSessionEntryPath: "/nextcloud/example-login", LoginChallengeCookieName: "example_login-challenge"}); err != nil {
		t.Fatal(err)
	}
}

func TestAuthIdentityFixedCopiesAndCookies(t *testing.T) {
	value := IdentityConfig{LoginTitle: "Example Login", LoginChallengeCookieName: "example_challenge", TOTPIssuer: " Example Issuer ", NextcloudSessionEntryPath: "/nextcloud/example-login"}
	useTestIdentity(t, value)
	value.LoginTitle = "caller mutation"
	copy := CurrentIdentity()
	copy.LoginTitle = "getter mutation"
	if CurrentIdentity().LoginTitle != "Example Login" || ConfigureIdentity(IdentityConfig{}) == nil {
		t.Fatal("authentication identity was not fixed")
	}
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	setChallengeCookie(w, r, "synthetic-challenge")
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "example_challenge" || !cookies[0].HttpOnly || cookies[0].MaxAge != loginChallengeCookieAge {
		t.Fatal("configured challenge cookie not issued")
	}
	w = httptest.NewRecorder()
	clearChallengeCookie(w, r)
	if c := w.Result().Cookies(); len(c) != 1 || c[0].Name != "example_challenge" || c[0].MaxAge >= 0 {
		t.Fatal("configured challenge cookie not cleared")
	}
	u, err := url.Parse(TOTPProvisioningURI("", "example-user", "JBSWY3DPEHPK3PXP"))
	if err != nil || u.Query().Get("issuer") != "Example Issuer" {
		t.Fatal("configured TOTP issuer lost")
	}
	if got := ncSessionLinkFor("https://example.com/nextcloud", "/monitor/?view=example"); got != "/nextcloud/example-login?next=%2Fmonitor%2F%3Fview%3Dexample" {
		t.Fatalf("configured SSO entry changed next encoding: %q", got)
	}
}

func TestAuthIdentityLoginTemplateEscapesCustomText(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	t.Setenv("HEARTDESK_USERS_TOML", "")
	t.Setenv("HEARTDESK_USERS_JSON", "")
	t.Setenv("HEARTDESK_TENANT_ID", "")
	useTestIdentity(t, IdentityConfig{LoginTitle: "Example <Login>", LoginSubtitle: "A & B"})
	useNCSessionTestDefaults(t, map[string]User{})
	tmpl, err := template.New("").ParseFS(web.Templates(), "login.html")
	if err != nil {
		t.Fatal(err)
	}
	h := NewHTTPHandler(tmpl, routing.Current(), config.CardsConfig{}, config.SystemInfoData{})
	w := httptest.NewRecorder()
	h.Login(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "<title>Example &lt;Login&gt;</title>") || !strings.Contains(body, "A &amp; B") || strings.Contains(body, "<title>heartdesk</title>") {
		t.Fatalf("custom login identity not escaped/rendered: status%d", w.Code)
	}
}

func TestAuthIdentityCustomChallengeResume(t *testing.T) {
	useTestIdentity(t, IdentityConfig{LoginChallengeCookieName: "example_challenge"})
	useNCSessionTestDefaults(t, map[string]User{})
	tmpl := template.Must(template.New("").Parse(`{{define "login"}}{{.Stage}}|{{.Username}}{{end}}`))
	h := NewHTTPHandler(tmpl, routing.Current(), config.CardsConfig{}, config.SystemInfoData{})
	challenge, err := DefaultLoginChallengeManager().Create(User{Username: "example-user"}, "/monitor/", "192.0.2.1", "synthetic-client")
	if err != nil {
		t.Fatal(err)
	}
	defer DefaultLoginChallengeManager().Delete(challenge.ID)
	for _, tc := range []struct{ cookie, want string }{{"example_challenge", "totp|example-user"}, {loginChallengeCookie, "password|"}} {
		r := httptest.NewRequest(http.MethodGet, "/login", nil)
		r.AddCookie(&http.Cookie{Name: tc.cookie, Value: challenge.ID})
		w := httptest.NewRecorder()
		h.Login(w, r)
		if w.Body.String() != tc.want {
			t.Fatalf("cookie %s: got %q want %q", tc.cookie, w.Body.String(), tc.want)
		}
	}
}

func TestAuthIdentityCustomNCMessageKeepsDisabledRejection(t *testing.T) {
	useTestIdentity(t, IdentityConfig{NextcloudNotRegisteredMessage: "Example account is not registered."})
	h := ncMessageTestHandler(t)
	swapNCMessageTestStore(t, nil)
	if body := ncMessageTestLogin(t, h, "example-unregistered"); !strings.Contains(body, "Example account is not registered.") {
		t.Fatal("custom unregistered message not shown")
	}
	swapNCMessageTestStore(t, map[string]User{"example-disabled": {ID: "example-disabled", Username: "example-disabled", Disabled: true, AccessScreens: []string{"monitor"}}})
	if body := ncMessageTestLogin(t, h, "example-disabled"); !strings.Contains(body, genericLoginError) || strings.Contains(body, "Example account is not registered.") {
		t.Fatal("disabled account rejection changed")
	}
}
