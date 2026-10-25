package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/ishizakahiroshi/heartdesk/app"
	vendorconsole "github.com/ishizakahiroshi/heartdesk/core/vendor_console"
	"github.com/ishizakahiroshi/heartpost/agentsig"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCustomLicenseIdentityAcrossIssueHeartbeatReportAndOffline(t *testing.T) {
	if os.Getenv("HEARTDESK_TEST_CUSTOM_IDENTITY") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCustomLicenseIdentityAcrossIssueHeartbeatReportAndOffline$")
		cmd.Env = append(os.Environ(), "HEARTDESK_TEST_CUSTOM_IDENTITY=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
	opts := testOptions(t)
	strict := true
	opts.Config.AgentReport.StrictLicense = &strict
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	opts.Config.AgentKeys = map[string]string{"alpha-vps-example": "synthetic-agent-hmac"}
	opts.Config.AgentAllowedIPs = map[string][]string{"alpha-vps-example": {"192.0.2.1"}}
	opts.Config.VendorLicense.ActiveKID = "synthetic"
	opts.Config.VendorLicense.SigningKeys = map[string]app.SigningKeyEntry{"synthetic": {State: "active", PublicKeyB64: base64.StdEncoding.EncodeToString(pub), PrivateKeyB64: base64.StdEncoding.EncodeToString(priv)}}
	material := app.LicenseConfig{VendorSecret: "synthetic-vendor-material", Issuer: "example-vendor", Audience: "example-monitor", OfflineAudience: "example-agent", OfflineType: "example-offline-license", OfflineFilenameExtension: ".examplelic"}
	opts.LicenseConfig = &material
	rt, err := app.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	material.Issuer = "caller mutation"
	if err := rt.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	request := func(path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://example.com"+path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("X-Agent-Id", "alpha-vps-example")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if path == "/api/agent/report" {
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			r.Header.Set("X-Agent-Timestamp", ts)
			r.Header.Set("X-Agent-Signature", agentsig.Compute("synthetic-agent-hmac", ts, []byte(body)))
		}
		w := httptest.NewRecorder()
		rt.Handler().ServeHTTP(w, r)
		return w
	}
	mac := hmac.New(sha256.New, []byte("synthetic-vendor-material"))
	mac.Write([]byte("alpha.alpha-vps-example"))
	key := "alpha.alpha-vps-example." + hex.EncodeToString(mac.Sum(nil))
	body, _ := json.Marshal(map[string]string{"agent_id": "alpha-vps-example", "license_key": key})
	issued := request("/api/license/verify", string(body), "")
	if issued.Code != 200 {
		t.Fatalf("issue: %d %s", issued.Code, issued.Body.String())
	}
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(issued.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	decode := func(token string) map[string]interface{} {
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatal("expected JWT")
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
			t.Fatal("invalid signed JWT")
		}
		claims, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal(claims, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	claims := decode(response.Token)
	if claims["iss"] != "example-vendor" || claims["aud"] != "example-monitor" {
		t.Fatal("issued identity mismatch")
	}
	renewed := request("/api/license/heartbeat", "", response.Token)
	if renewed.Code != 200 {
		t.Fatalf("heartbeat: %d %s", renewed.Code, renewed.Body.String())
	}
	if err := json.Unmarshal(renewed.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	claims = decode(response.Token)
	if claims["iss"] != "example-vendor" || claims["aud"] != "example-monitor" {
		t.Fatal("heartbeat changed identity")
	}
	report := `{"agent_id":"alpha-vps-example","collectors":{}}`
	if w := request("/api/agent/report", report, response.Token); w.Code != 200 {
		t.Fatalf("custom report: %d %s", w.Code, w.Body.String())
	}
	for _, field := range []string{"iss", "aud"} {
		wrong := decode(response.Token)
		wrong[field] = "other-application"
		payload, _ := json.Marshal(wrong)
		parts := strings.Split(response.Token, ".")
		message := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
		token := message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(message)))
		if w := request("/api/agent/report", report, token); w.Code != 401 {
			t.Fatalf("wrong %s accepted: %d", field, w.Code)
		}
		if w := request("/api/license/heartbeat", "", token); w.Code != 401 {
			t.Fatalf("wrong heartbeat %s accepted: %d", field, w.Code)
		}
	}
	offline, err := vendorconsole.IssueOfflineLicenseJWT(rt.Config(), "alpha-vps-example", 30, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Header struct {
			Typ string `json:"typ"`
		} `json:"header"`
		Claims map[string]interface{} `json:"claims"`
	}
	if err := json.Unmarshal(offline, &file); err != nil {
		t.Fatal(err)
	}
	if file.Header.Typ != "example-offline-license" || file.Claims["iss"] != "example-vendor" || file.Claims["aud"] != "example-agent" {
		t.Fatal("offline identity mismatch")
	}
	if err := app.DefaultStore().AddUser("example", "Example", "vendor_staff", "synthetic-password"); err != nil {
		t.Fatal(err)
	}
	u, _ := app.DefaultStore().GetUser("example")
	u.AccessScreens = []string{"monitor", "vendor"}
	session, err := app.DefaultSessionManager().Create(u, "192.0.2.1", "synthetic-client", rt.Config().Cards, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://example.com/monitor/?api=vendor_license_offline_generate", strings.NewReader("agent_id=alpha-vps-example"))
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "synthetic-client")
	r.Header.Set("X-Requested-With", "XMLHttpRequest")
	r.Header.Set("X-CSRF-Token", session.CSRFToken)
	r.AddCookie(&http.Cookie{Name: "example_session", Value: session.ID})
	r.AddCookie(&http.Cookie{Name: "example_csrf", Value: session.CSRFToken})
	w := httptest.NewRecorder()
	rt.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("offline download: %d %s", w.Code, w.Body.String())
	}
	var download struct {
		Filename string `json:"filename"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &download); err != nil {
		t.Fatal(err)
	}
	if download.Filename != "license_alpha-vps-example.examplelic" {
		t.Fatal("offline filename extension ignored", download.Filename)
	}
}
