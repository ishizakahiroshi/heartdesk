package license

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// vendorSecret は license_key の署名（HMAC-SHA256）に使う鍵で、ライセンスを発行する側が管理する秘密。
// ビルド時に次のように注入する（モジュールパスまで含めて指定する）:
//
//	go build -ldflags "-X github.com/ishizakahiroshi/heartdesk/internal/license.vendorSecret=<secret>" .
//
// ソースに既定値を持たせず、注入しないと起動できない作りにしている。理由は、この値を知る者は
// 誰でも有効な license_key を作れるため、ソースに書くと公開された時点で署名が意味を失うから。
// 値は自分で決めた任意の秘密でよいが、license_key を計算する側（Monitor 自身の
// [vendor_license] と /api/license/verify で検証する各 Agent のキー）も同じ値で署名すること。
// 値はバイナリに埋め込まれるので、バイナリも秘密として扱う。
var vendorSecret = ""

type verifierImpl struct {
	mu           sync.RWMutex
	currentToken string
}

func newVerifier() Verifier {
	return &verifierImpl{}
}

// CurrentToken は最新の検証済み Bearer JWT を返す。トークン未取得時は空文字。
func (v *verifierImpl) CurrentToken() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.currentToken
}

// SetCurrentToken は最新トークンを Verifier 内に保存する。
func (v *verifierImpl) SetCurrentToken(token string) {
	v.mu.Lock()
	v.currentToken = token
	v.mu.Unlock()
}

// Verify はライセンスキーの形式と署名を検証する。
// license_key の形式: "<tenant_id>.<agent_id>.<hmac_signature>"
func (v *verifierImpl) Verify(agentID, licenseKey string) error {
	if vendorSecret == "" {
		return fmt.Errorf("license: vendorSecret not injected at build time; " +
			"rebuild with -ldflags \"-X github.com/ishizakahiroshi/heartdesk/internal/license.vendorSecret=<secret>\"")
	}
	if licenseKey == "" {
		return fmt.Errorf("license: license_key is not set in agent_secrets.toml")
	}

	parts := strings.SplitN(licenseKey, ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("license: invalid license_key format")
	}
	tenantID, keyAgentID, sig := parts[0], parts[1], parts[2]

	// agent_id のテナントプレフィクスと一致するか確認
	if !strings.HasPrefix(agentID, tenantID+"-") {
		return fmt.Errorf("license: agent_id %q does not belong to tenant %q", agentID, tenantID)
	}
	// キー内の agent_id と実際の agent_id が一致するか確認
	if keyAgentID != agentID {
		return fmt.Errorf("license: license_key is issued for %q, but agent_id is %q", keyAgentID, agentID)
	}

	// HMAC-SHA256 署名検証
	expected := computeSig(tenantID, agentID, vendorSecret)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return fmt.Errorf("license: invalid license_key signature")
	}

	return nil
}

// ComputeLicenseSig は鍵引数版の署名ヘルパ。license_key の署名部分
// HMAC-SHA256(key, tenantID + "." + agentID) を 16 進数で返す。
// Verify / ComputeVendorLicenseSig はビルド注入 vendorSecret を、Vendor Console の
// GenerateLicenseKey は cfg.VendorLicense.LicenseKey / cfg.AgentKeys[agentID] を鍵に渡す。
// 鍵が異なるだけで計算式は同一のため、発行側と検証側でロジックを 1 箇所に集約する
// （C7-C2: hmac-sign-logic-quadruplicated）。
func ComputeLicenseSig(key, tenantID, agentID string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(tenantID + "." + agentID))
	return hex.EncodeToString(mac.Sum(nil))
}

func computeSig(tenantID, agentID, secret string) string {
	return ComputeLicenseSig(secret, tenantID, agentID)
}

// ComputeVendorLicenseSig はビルド時に注入された vendorSecret を使って
// license_key の署名部分（HMAC-SHA256 hex）を計算する。
// Monitor / Vendor / Agent すべてここを経由することで署名ロジックを1箇所に集約する。
// vendorSecret 未注入時は空文字と false を返す。
func ComputeVendorLicenseSig(tenantID, agentID string) (string, bool) {
	if vendorSecret == "" {
		return "", false
	}
	return computeSig(tenantID, agentID, vendorSecret), true
}

// VerifyWithMonitor は Monitor の /api/license/verify を呼び出してトークンを取得する。
// monitorEndpoint が空の場合はスキップして "" を返す。
// 成功時はトークン文字列を返す。
func (v *verifierImpl) VerifyWithMonitor(ctx context.Context, agentID, licenseKey, monitorEndpoint string) (string, error) {
	if monitorEndpoint == "" || monitorEndpoint == "http://localhost" {
		return "", nil
	}

	url := strings.TrimRight(monitorEndpoint, "/") + "/api/license/verify"

	body, _ := json.Marshal(map[string]string{
		"agent_id":    agentID,
		"license_key": licenseKey,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("license: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("license: monitor verify request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("license: monitor rejected license (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("license: monitor verify returned status %d", resp.StatusCode)
	}

	var result struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("license: decode verify response: %w", err)
	}
	if !result.OK || result.Token == "" {
		return "", fmt.Errorf("license: monitor returned ok=false or empty token")
	}

	return result.Token, nil
}

// StartHeartbeat は interval ごとに /api/license/heartbeat を叩き、トークンを延長する。
// 401/403 応答を受けた場合は VerifyWithMonitor で再認証してgoroutineを継続する（Agent 再起動不要）。
// その他のエラー（5xx/ネットワーク障害）はログに残して継続し、次の interval で再試行する。
func (v *verifierImpl) StartHeartbeat(ctx context.Context, agentID, licenseKey, token, monitorEndpoint string, interval time.Duration) {
	if monitorEndpoint == "" || monitorEndpoint == "http://localhost" || token == "" {
		return
	}
	if interval <= 0 {
		interval = 6 * time.Hour
	}

	// 初期トークンを共有ストアに保存（main 側で SetCurrentToken 済みでも上書きは同値なので無害）
	v.SetCurrentToken(token)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		url := strings.TrimRight(monitorEndpoint, "/") + "/api/license/heartbeat"

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				newToken, err := sendHeartbeat(ctx, url, agentID, v.CurrentToken())
				if err != nil {
					if isRevoked(err) {
						reToken, rerr := v.VerifyWithMonitor(ctx, agentID, licenseKey, monitorEndpoint)
						if rerr != nil {
							log.Printf("license: re-auth failed agent=%s: %v – will retry next interval", agentID, rerr)
							continue
						}
						v.SetCurrentToken(reToken)
						log.Printf("license: re-auth ok agent=%s – heartbeat resumed", agentID)
						continue
					}
					log.Printf("license: heartbeat error agent=%s: %v (will retry)", agentID, err)
				} else if newToken != "" {
					v.SetCurrentToken(newToken)
				}
			}
		}
	}()
}

func isJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

func sendHeartbeat(ctx context.Context, url, agentID, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Agent-Id", agentID)
	if isJWT(token) {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("X-License-Token", token)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", &revokedError{status: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("heartbeat returned status %d", resp.StatusCode)
	}

	var result struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("heartbeat decode response: %w", err)
	}
	return result.Token, nil
}

type revokedError struct{ status int }

func (e *revokedError) Error() string { return fmt.Sprintf("license revoked (status %d)", e.status) }

func isRevoked(err error) bool {
	_, ok := err.(*revokedError)
	return ok
}

// VerifyToken はMonitorから受け取ったJWT（ed25519署名）を検証しclaimsを返す。
// ビルド時注入の公開鍵で署名を確認し、有効期限・agentIDの一致も検証する。
func (v *verifierImpl) VerifyToken(agentID, token string) (*Claims, error) {
	resolver, err := VendorPublicKeyResolver()
	if err != nil {
		return nil, fmt.Errorf("license: public key parse failed: %w", err)
	}
	claims, err := VerifyJWT(token, resolver)
	if err != nil {
		return nil, err
	}
	if claims.Subject != agentID {
		return nil, fmt.Errorf("license: token subject %q != agent_id %q", claims.Subject, agentID)
	}
	return claims, nil
}

// VerifyOfflineLicense はオフラインライセンスファイルを検証してclaimsを返す。
// Monitor不到達時のフォールバックとして使用する。
func (v *verifierImpl) VerifyOfflineLicense(agentID, filePath string) (*Claims, error) {
	resolver, err := VendorPublicKeyResolver()
	if err != nil {
		return nil, fmt.Errorf("license: public key parse failed: %w", err)
	}
	claims, err := LoadAndVerifyOfflineLicense(filePath, resolver)
	if err != nil {
		return nil, err
	}
	if claims.Subject != agentID {
		return nil, fmt.Errorf("license: offline license issued for %q but agent_id is %q", claims.Subject, agentID)
	}
	// 未来すぎるiat（時計ずらし対策）
	const maxFutureSkew = 24 * 60 * 60 // 24h in seconds
	nowSec := time.Now().Unix()
	if claims.IssuedAt > nowSec+maxFutureSkew {
		return nil, fmt.Errorf("license: offline license iat is too far in the future")
	}
	return claims, nil
}
