package monitor

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/license"
)

// licenseTokenTTL はトークンのデフォルト有効期間（72h = フェイルモード猶予と同値）
const licenseTokenTTL = 72 * time.Hour

// jtiEntry はJTI（JWT ID）の発行/失効管理エントリ。
type jtiEntry struct {
	AgentID   string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

var (
	jtiMu       sync.RWMutex
	issuedJTIs  = map[string]*jtiEntry{} // jti → entry
	revokedJTIs = map[string]revokedEntry{}

	// 後方互換: HMAC トークン管理（旧フォーマットのAgentが接続している間も使用）
	legacyTokensMu sync.RWMutex
	legacyTokens   = map[string]*legacyTokenEntry{} // agentID → entry
)

type legacyTokenEntry struct {
	Token     string
	AgentID   string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// licenseVerifyMaxBody は /api/license/verify の body 上限。
const licenseVerifyMaxBody = 64 << 10 // 64KiB

// LicenseVerifyHandler は POST /api/license/verify を処理する。
// Agent 起動時に呼ばれ、ライセンスキーを検証してJWTトークンを発行する。
func LicenseVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, licenseVerifyMaxBody)

	var req struct {
		AgentID    string `json:"agent_id"`
		LicenseKey string `json:"license_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if req.AgentID == "" || req.LicenseKey == "" {
		http.Error(w, `{"error":"agent_id and license_key are required"}`, http.StatusBadRequest)
		return
	}

	tenantID := tenantIDFromAgentID(req.AgentID)
	// 起動時ロード済みキャッシュを参照する。
	cfg, err := config.CachedAppConfigForTenant(tenantID)
	if err != nil {
		log.Printf("ERROR: license_api: config load error tenant=%s: %v", tenantID, err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	remoteIP := realIP(r)
	if err := verifyLicenseKey(req.AgentID, req.LicenseKey, cfg, remoteIP); err != nil {
		log.Printf("ERROR: license_api: verify failed agent=%s: %v", req.AgentID, err)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// ed25519 鍵が設定済みならJWT、未設定なら後方互換HMACトークンを発行
	token, kid, expiresAt, err := issueLicenseJWT(req.AgentID, cfg)
	if err != nil {
		log.Printf("WARN: license_api: JWT issue failed agent=%s: %v, falling back to HMAC", req.AgentID, err)
		legacyToken, legacyEntry := issueLegacyToken(req.AgentID, cfg)
		log.Printf("INFO: license_api: issued legacy token agent=%s expires=%s", req.AgentID, legacyEntry.ExpiresAt.Format(time.RFC3339))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":         true,
			"token":      legacyToken,
			"expires_at": legacyEntry.ExpiresAt.Format(time.RFC3339),
		})
		return
	}

	log.Printf("INFO: license_api: issued JWT agent=%s kid=%s expires=%s", req.AgentID, kid, expiresAt.Format(time.RFC3339))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":         true,
		"token":      token,
		"kid":        kid,
		"expires_at": expiresAt.Format(time.RFC3339),
	})
}

// LicenseHeartbeatHandler は POST /api/license/heartbeat を処理する。
// Agent が定期的（6時間ごと）に呼び出してトークンを更新する。
// Authorization: Bearer <jwt> または旧 X-License-Token ヘッダを受理する。
func LicenseHeartbeatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	agentID := strings.TrimSpace(r.Header.Get("X-Agent-Id"))
	if agentID == "" {
		http.Error(w, `{"error":"X-Agent-Id header required"}`, http.StatusBadRequest)
		return
	}

	// JWT パス: Authorization: Bearer <jwt>
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		jwtToken := strings.TrimPrefix(authHeader, "Bearer ")
		handleJWTHeartbeat(w, r, agentID, jwtToken)
		return
	}

	// 後方互換: X-License-Token ヘッダ
	legacyToken := strings.TrimSpace(r.Header.Get("X-License-Token"))
	if legacyToken == "" {
		http.Error(w, `{"error":"Authorization: Bearer or X-License-Token header required"}`, http.StatusBadRequest)
		return
	}
	handleLegacyHeartbeat(w, agentID, legacyToken)
}

func handleJWTHeartbeat(w http.ResponseWriter, r *http.Request, agentID, jwtToken string) {
	// JTI 抽出（署名検証前に失効チェック）
	claims, err := license.ExtractClaimsUnverified(jwtToken)
	if err != nil {
		http.Error(w, `{"error":"malformed token"}`, http.StatusBadRequest)
		return
	}
	if isJTIRevoked(claims.JTI) {
		log.Printf("WARN: license_api: heartbeat revoked JTI=%s agent=%s", claims.JTI, agentID)
		http.Error(w, `{"error":"token revoked"}`, http.StatusUnauthorized)
		return
	}

	// テナント設定をロードして新JWTを再発行
	tenantID, err := validateAgentIDTenant(agentID)
	if err != nil {
		http.Error(w, `{"error":"invalid agent_id format"}`, http.StatusBadRequest)
		return
	}
	// 起動時ロード済みキャッシュを参照する。
	cfg, err := config.CachedAppConfigForTenant(tenantID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	resolver, err := vendorPublicKeyResolver(cfg)
	if err != nil {
		log.Printf("ERROR: license_api: heartbeat resolver error agent=%s: %v", agentID, err)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	verifiedClaims, err := license.VerifyJWT(jwtToken, resolver)
	if err != nil {
		log.Printf("ERROR: license_api: heartbeat JWT verify failed agent=%s: %v", agentID, err)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if err := validateAgentSessionClaims(verifiedClaims, agentID, tenantID); err != nil {
		log.Printf("ERROR: license_api: heartbeat claims invalid agent=%s: %v", agentID, err)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	newToken, kid, expiresAt, err := issueLicenseJWT(agentID, cfg)
	if err != nil {
		// 再発行に失敗しても、現在のJWTがまだ有効ならその期限までは継続利用させる。
		log.Printf("WARN: license_api: JWT re-issue failed agent=%s, keeping existing token: %v", agentID, err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":         true,
			"expires_at": time.Unix(verifiedClaims.ExpiresAt, 0).UTC().Format(time.RFC3339),
		})
		return
	}

	log.Printf("INFO: license_api: JWT heartbeat ok agent=%s kid=%s new_expires=%s", agentID, kid, expiresAt.Format(time.RFC3339))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":         true,
		"token":      newToken,
		"kid":        kid,
		"expires_at": expiresAt.Format(time.RFC3339),
	})
}

func handleLegacyHeartbeat(w http.ResponseWriter, agentID, token string) {
	legacyTokensMu.Lock()
	entry, ok := legacyTokens[agentID]
	// レガシー token 比較は定数時間。
	if !ok || subtle.ConstantTimeCompare([]byte(entry.Token), []byte(token)) != 1 {
		legacyTokensMu.Unlock()
		log.Printf("WARN: license_api: heartbeat invalid token agent=%s", agentID)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if time.Now().After(entry.ExpiresAt) {
		legacyTokensMu.Unlock()
		log.Printf("WARN: license_api: heartbeat expired token agent=%s", agentID)
		http.Error(w, `{"error":"token expired"}`, http.StatusUnauthorized)
		return
	}
	entry.ExpiresAt = time.Now().Add(licenseTokenTTL)
	if err := persistLegacyTokenStoreLocked(); err != nil {
		log.Printf("ERROR: license_api: persist legacy token store failed agent=%s: %v", agentID, err)
	}
	legacyTokensMu.Unlock()

	log.Printf("INFO: license_api: legacy heartbeat ok agent=%s new_expires=%s", agentID, entry.ExpiresAt.Format(time.RFC3339))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":         true,
		"expires_at": entry.ExpiresAt.Format(time.RFC3339),
	})
}

// LicenseRevokeJTI は指定JTIを失効させる。
func LicenseRevokeJTI(jti string) {
	if jti == "" {
		return
	}

	jtiMu.Lock()
	defer jtiMu.Unlock()

	entry := revokedEntry{
		RevokedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if issued, ok := issuedJTIs[jti]; ok {
		entry.AgentID = issued.AgentID
		entry.ExpiresAt = issued.ExpiresAt.UTC().Format(time.RFC3339)
	}
	revokedJTIs[jti] = entry
	if err := persistRevokedJTIStoreLocked(); err != nil {
		log.Printf("ERROR: license_api: persist revoke store failed jti=%s: %v", jti, err)
	}
}

// LicenseRevokeAgent はagentIDに紐づく全JTIを失効させる。
func LicenseRevokeAgent(agentID string) {
	if agentID == "" {
		return
	}

	jtiMu.Lock()
	defer jtiMu.Unlock()

	revokedAt := time.Now().UTC().Format(time.RFC3339)
	for jti, entry := range issuedJTIs {
		if entry.AgentID == agentID {
			revokedJTIs[jti] = revokedEntry{
				AgentID:   entry.AgentID,
				RevokedAt: revokedAt,
				ExpiresAt: entry.ExpiresAt.UTC().Format(time.RFC3339),
			}
		}
	}
	if err := persistRevokedJTIStoreLocked(); err != nil {
		log.Printf("ERROR: license_api: persist revoke store failed agent=%s: %v", agentID, err)
	}
}

// verifyLicenseKey はライセンスキーの形式・署名・AgentKeys登録・IP制限を検証する。
// 形式: "<tenant_id>.<agent_id>.<hmac_signature>"
func verifyLicenseKey(agentID, licenseKey string, cfg *config.AppConfig, remoteIP string) error {
	parts := strings.SplitN(licenseKey, ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid license_key format")
	}
	tenantID, keyAgentID, sig := parts[0], parts[1], parts[2]

	if !strings.HasPrefix(agentID, tenantID+"-") {
		return fmt.Errorf("agent_id %q does not belong to tenant %q", agentID, tenantID)
	}
	if keyAgentID != agentID {
		return fmt.Errorf("license_key issued for %q but agent_id is %q", keyAgentID, agentID)
	}

	// agent_id が secrets.toml の [agent_keys] に登録されていることを確認する
	// （agentKey は HMAC リクエスト署名用。license_key 検証は vendorSecret で行う）
	if cfg.AgentKeys == nil || cfg.AgentKeys[agentID] == "" {
		return fmt.Errorf("unknown agent_id: %s", agentID)
	}

	// license_key の署名は Vendor（ビルド時注入の vendorSecret）で検証する
	expected, ok := license.ComputeVendorLicenseSig(tenantID, agentID)
	if !ok {
		return fmt.Errorf("vendorSecret not injected at build time")
	}
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return fmt.Errorf("invalid license_key signature")
	}

	if err := checkAgentIP(agentID, remoteIP, cfg); err != nil {
		return err
	}

	if err := checkAgentQuota(tenantID, cfg); err != nil {
		return err
	}

	return nil
}

// checkAgentIP は agent_allowed_ips の制限を検証する。
// 許可リストが未設定または空の場合は拒否（デフォルト拒否）。
func checkAgentIP(agentID, remoteIP string, cfg *config.AppConfig) error {
	allowedIPs := []string{}
	if cfg.AgentAllowedIPs != nil {
		allowedIPs = cfg.AgentAllowedIPs[agentID]
	}
	if len(allowedIPs) == 0 {
		log.Printf("WARN: license_api: no allowed_ips configured agent=%s remote_ip=%s", agentID, remoteIP)
		return fmt.Errorf("no allowed IPs configured for agent %q", agentID)
	}

	// remoteIP は "x.x.x.x:port" や IPv6 の "[::1]:port" 形式の場合があるため
	// net.SplitHostPort でポートを除去する。ポートが無く SplitHostPort が失敗した
	// 場合は remoteIP をそのまま IP 文字列とみなす。
	host := remoteIP
	if h, _, err := net.SplitHostPort(remoteIP); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		log.Printf("WARN: license_api: unparseable remote_ip agent=%s remote_ip=%s", agentID, remoteIP)
		return fmt.Errorf("unparseable remote IP %q for agent %q", remoteIP, agentID)
	}

	// allowed エントリは単一 IP（完全一致）と CIDR（レンジ判定）の両方を受け付ける。
	// パース不能なエントリは握りつぶさず warning を出してスキップする。
	for _, allowed := range allowedIPs {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		if strings.Contains(allowed, "/") {
			_, ipNet, err := net.ParseCIDR(allowed)
			if err != nil {
				log.Printf("WARN: license_api: invalid CIDR in allowed_ips agent=%s entry=%q: %v", agentID, allowed, err)
				continue
			}
			if ipNet.Contains(ip) {
				return nil
			}
			continue
		}
		allowedIP := net.ParseIP(allowed)
		if allowedIP == nil {
			log.Printf("WARN: license_api: invalid IP in allowed_ips agent=%s entry=%q", agentID, allowed)
			continue
		}
		if allowedIP.Equal(ip) {
			return nil
		}
	}
	log.Printf("WARN: license_api: IP not allowed agent=%s remote_ip=%s", agentID, ip.String())
	return fmt.Errorf("IP address %q is not allowed for agent %q", ip.String(), agentID)
}

// issueLicenseJWT はed25519署名のJWTを発行してJTI管理mapに登録する。
// 署名鍵が設定されていない場合はエラーを返す（呼び出し元でHMACにフォールバック）。
func issueLicenseJWT(agentID string, cfg *config.AppConfig) (token, kid string, expiresAt time.Time, err error) {
	activeKID := cfg.VendorLicense.ActiveKID
	if activeKID == "" {
		return "", "", time.Time{}, fmt.Errorf("active_kid not set")
	}
	keyEntry, ok := cfg.VendorLicense.SigningKeys[activeKID]
	if !ok {
		return "", "", time.Time{}, fmt.Errorf("signing key %q not found", activeKID)
	}
	if keyEntry.State != "active" {
		return "", "", time.Time{}, fmt.Errorf("signing key %q is not active (state=%s)", activeKID, keyEntry.State)
	}

	privBytes, err := base64.StdEncoding.DecodeString(keyEntry.PrivateKeyB64)
	if err != nil {
		privBytes, err = base64.RawStdEncoding.DecodeString(keyEntry.PrivateKeyB64)
		if err != nil {
			return "", "", time.Time{}, fmt.Errorf("decode private key: %w", err)
		}
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return "", "", time.Time{}, fmt.Errorf("invalid private key size: %d", len(privBytes))
	}
	priv := ed25519.PrivateKey(privBytes)

	jti, err := license.NewJTI()
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("generate JTI: %w", err)
	}

	tenantID := tenantIDFromAgentID(agentID)
	now := time.Now()
	exp := now.Add(licenseTokenTTL)

	claims := license.Claims{
		Issuer:    "sab-vendor",
		Subject:   agentID,
		Audience:  "sab-monitor",
		TenantID:  tenantID,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
		NotBefore: now.Unix(),
		JTI:       jti,
		Scope:     "agent.report",
		Type:      "session",
	}

	jwtToken, err := license.SignJWT(priv, activeKID, claims)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("sign JWT: %w", err)
	}

	jtiMu.Lock()
	pruneIssuedJTIsLocked(now)
	issuedJTIs[jti] = &jtiEntry{
		AgentID:   agentID,
		IssuedAt:  now,
		ExpiresAt: exp,
	}
	jtiMu.Unlock()

	return jwtToken, activeKID, exp, nil
}

func validateAgentSessionClaims(claims *license.Claims, agentID, tenantID string) error {
	if claims == nil {
		return fmt.Errorf("missing claims")
	}
	if claims.Subject != agentID {
		return fmt.Errorf("agent_id mismatch")
	}
	if claims.TenantID != tenantID {
		return fmt.Errorf("tenant_id mismatch")
	}
	if claims.Audience != "sab-monitor" {
		return fmt.Errorf("invalid audience")
	}
	if claims.Issuer != "sab-vendor" {
		return fmt.Errorf("invalid issuer")
	}
	if claims.Scope != "agent.report" {
		return fmt.Errorf("invalid scope")
	}
	if claims.Type != "session" {
		return fmt.Errorf("invalid token type")
	}
	return nil
}

func pruneIssuedJTIsLocked(now time.Time) {
	for jti, entry := range issuedJTIs {
		if entry == nil || now.After(entry.ExpiresAt) {
			delete(issuedJTIs, jti)
		}
	}
}

// issueLegacyToken は後方互換用のHMACトークンを発行する。
func issueLegacyToken(agentID string, cfg *config.AppConfig) (string, *legacyTokenEntry) {
	secretKey := ""
	if cfg.AgentKeys != nil {
		secretKey = cfg.AgentKeys[agentID]
	}

	now := time.Now()
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(fmt.Sprintf("%s.%d", agentID, now.UnixNano())))
	token := hex.EncodeToString(mac.Sum(nil))

	entry := &legacyTokenEntry{
		Token:     token,
		AgentID:   agentID,
		IssuedAt:  now,
		ExpiresAt: now.Add(licenseTokenTTL),
	}

	legacyTokensMu.Lock()
	legacyTokens[agentID] = entry
	if err := persistLegacyTokenStoreLocked(); err != nil {
		log.Printf("ERROR: license_api: persist legacy token store failed agent=%s: %v", agentID, err)
	}
	legacyTokensMu.Unlock()

	return token, entry
}

// checkAgentQuota はテナントの Agent 台数上限を検証する。
// agent_quota が未設定または 0 の場合は制限なし。
func checkAgentQuota(tenantID string, cfg *config.AppConfig) error {
	if cfg.AgentQuota == nil {
		return nil
	}
	quota, ok := cfg.AgentQuota[tenantID]
	if !ok || quota <= 0 {
		return nil
	}
	count := 0
	prefix := tenantID + "-"
	for agentID := range cfg.AgentKeys {
		if strings.HasPrefix(agentID, prefix) {
			count++
		}
	}
	if count > quota {
		log.Printf("WARN: license_api: quota exceeded tenant=%s registered=%d quota=%d", tenantID, count, quota)
		return fmt.Errorf("agent quota exceeded for tenant %q (%d/%d)", tenantID, count, quota)
	}
	return nil
}

// realIP はクライアント IP を trustedProxy 層経由で返す。
//
// auth.TrustedClientIP に委譲する。
// RemoteAddr が信頼プロキシ（loopback / 登録 nginx）のときのみ X-Real-IP を採用し、
// :8765 直結時はヘッダを無視して RemoteAddr を使う。
func realIP(r *http.Request) string {
	return auth.TrustedClientIP(r)
}
