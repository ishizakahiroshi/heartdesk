package monitor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/audit"
	"github.com/ishizakahiroshi/heartdesk/internal/auditdb"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/license"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"
	"github.com/ishizakahiroshi/heartpost/agentsig"
)

func agentReportDirPath() string { return heartdesk.Path("data/json/agent_reports") }

// AgentReport は Agent から受信するレポートの全体構造
type AgentReport struct {
	AgentID    string                     `json:"agent_id"`
	AgentLabel string                     `json:"agent_label"`
	AgentType  string                     `json:"agent_type"` // "vps" | "rental"
	ReportedAt string                     `json:"reported_at"`
	Collectors map[string]json.RawMessage `json:"collectors"`
}

type agentReportRecord struct {
	ReceivedAt string                     `json:"received_at"`
	AgentID    string                     `json:"agent_id"`
	AgentLabel string                     `json:"agent_label"`
	AgentType  string                     `json:"agent_type"`
	ReportedAt string                     `json:"reported_at"`
	Collectors map[string]json.RawMessage `json:"collectors"`
}

// AgentLastSeen はエージェントの最終受信情報
type AgentLastSeen struct {
	AgentID           string `json:"agent_id"`
	AgentLabel        string `json:"agent_label"`
	AgentType         string `json:"agent_type"`
	ReceivedAt        string `json:"received_at"`
	ReceivedAtDisplay string `json:"-"`
	MinutesAgo        int    `json:"minutes_ago"`
	IsAlert           bool   `json:"is_alert"`
}

var (
	agentLastSeenMu       sync.RWMutex
	agentLastSeen         = map[string]*AgentLastSeen{}
	agentLatestCollectors = map[string]map[string]json.RawMessage{}
	tenantStore           store.TenantStore
	agentStore            store.AgentStore
	reportStore           store.ReportStore
	ledgerStore           store.LedgerStore
	agentStoreMu          sync.RWMutex
	tenantIDPattern       = regexp.MustCompile(`^[a-z0-9_]+$`)
	reportFilenamePattern = regexp.MustCompile(`^report_(.+)_\d{6}\.jsonl$`)
	// agentIDPattern は agent_id 全体の厳格バリデータ。
	// 例: alpha-vps-host1 / beta-rental-host2。パス連結前に必ずこのパターンを通す。
	agentIDPattern = regexp.MustCompile(`^[a-z0-9_]+-[a-z0-9_][a-z0-9_-]*$`)
)

// isValidAgentID は agent_id 全体が厳格パターンに合致するかを返す。
// パス/ファイル名連結前のトラバーサル防止用。
func isValidAgentID(agentID string) bool {
	return agentIDPattern.MatchString(strings.TrimSpace(agentID))
}

// SetAgentReportStores injects the vendorsvc SQLite stores used as the
// canonical Agent report datastore. If unset, Monitor falls back to legacy JSONL.
func SetAgentReportStores(stores *store.Stores) {
	agentStoreMu.Lock()
	defer agentStoreMu.Unlock()
	if stores == nil {
		tenantStore = nil
		agentStore = nil
		reportStore = nil
		ledgerStore = nil
		return
	}
	tenantStore = stores.Tenant
	agentStore = stores.Agent
	reportStore = stores.Report
	ledgerStore = stores.Ledger
}

func currentAgentReportStores() (store.TenantStore, store.AgentStore, store.ReportStore, bool) {
	agentStoreMu.RLock()
	defer agentStoreMu.RUnlock()
	ok := tenantStore != nil && agentStore != nil && reportStore != nil
	return tenantStore, agentStore, reportStore, ok
}

// currentLedgerStore は vendor ライセンス台帳の SQLite 正本を返す。
// 未配線時は ok=false（DB 未初期化）。
func currentLedgerStore() (store.LedgerStore, bool) {
	agentStoreMu.RLock()
	defer agentStoreMu.RUnlock()
	if ledgerStore == nil {
		return nil, false
	}
	return ledgerStore, true
}

// ledgerStr は store.LedgerEntry の *string フィールドを表示用に安全に展開する。
func ledgerStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// ledgerPtr は空文字を nil（SQL NULL）へ、非空をポインタへ変換する。
func ledgerPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// agentIDFromReportFilename は "report_<agent_id>_<YYYYMM>.jsonl" から agent_id を抽出する。
// パターンに合致しない場合は空文字を返す。
func agentIDFromReportFilename(name string) string {
	m := reportFilenamePattern.FindStringSubmatch(name)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

// tenantIDFromAgentID は "<tenant_id>-<type>-<name>" 形式の Agent ID からテナント ID を抽出する。
// 形式が一致しない場合は空文字を返す（呼び出し元がデフォルト値を適用する）。
func tenantIDFromAgentID(agentID string) string {
	// 期待フォーマット: <tenant_id>-<type>-<name>（例: alpha-rental-host2）
	idx := strings.Index(agentID, "-")
	if idx <= 0 {
		return ""
	}
	return agentID[:idx]
}

func isValidTenantID(tenantID string) bool {
	return tenantIDPattern.MatchString(tenantID)
}

func validateAgentIDTenant(agentID string) (string, error) {
	// tenant プレフィックスだけでなく agent_id 全体の
	// 文字種を厳格検証する。これにより `..` / `/` 等を含む agent_id がパス連結に到達しない。
	if !isValidAgentID(agentID) {
		return "", fmt.Errorf("invalid agent_id format: %s", agentID)
	}
	tenantID := tenantIDFromAgentID(agentID)
	if tenantID == "" || !isValidTenantID(tenantID) {
		return "", fmt.Errorf("invalid agent_id format: %s", agentID)
	}
	return tenantID, nil
}

// safeAgentPathJoin は base ディレクトリ配下に収まる安全なパスを返す。
// agent_id 由来のファイル名連結後、filepath.Clean +
// base 接頭辞チェックで base 配下外への書込み（パストラバーサル）を拒否する。
func safeAgentPathJoin(base, name string) (string, error) {
	cleaned := filepath.Clean(filepath.Join(base, name))
	baseClean := filepath.Clean(base)
	if cleaned != baseClean && !strings.HasPrefix(cleaned, baseClean+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes base directory: base=%s name=%s", base, name)
	}
	return cleaned, nil
}

// agentRemoteAddrHost は r.RemoteAddr から host 部（ポート除去）を返す。
func agentRemoteAddrHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

// isLoopbackHost は host（ポートなし IP 文字列）がループバックかを返す。
func isLoopbackHost(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

// agentReportStrict は StrictLicense（Bearer/JWT 必須）の有効値を返す。
// 既定（未設定/nil）は厳格（true）。
// LoadAppConfigForTenant の applyDefaults で nil は埋まるが、直接構築された
// AppConfig に対しても安全側（厳格）に倒すため nil を true として扱う。
func agentReportStrict(cfg *config.AppConfig) bool {
	if cfg.AgentReport.StrictLicense == nil {
		return true
	}
	return *cfg.AgentReport.StrictLicense
}

// agentReportConfigForTenant は報告元の設定に、集約先テナントの署名鍵だけを合わせる。
// IP 制限・local 用の鍵・ライセンス設定は報告元のものを保ち、共有キャッシュは変更しない。
func agentReportConfigForTenant(tenantID string) (*config.AppConfig, error) {
	cfg, err := config.CachedAppConfigForTenant(tenantID)
	if err != nil || config.ResolveTenantID(tenantID) == config.DefaultTenantID {
		return cfg, err
	}
	aggregatorCfg, err := config.CachedAppConfigForTenant(config.DefaultTenantID)
	if err != nil {
		return nil, fmt.Errorf("aggregator config load failed: %w", err)
	}
	reportCfg := *cfg
	reportCfg.AggregatorAgentKeys = aggregatorCfg.AggregatorAgentKeys
	return &reportCfg, nil
}

// AgentReportHandler は POST /api/agent/report を処理する
func AgentReportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	agentID := strings.TrimSpace(r.Header.Get("X-Agent-Id"))
	if agentID == "" {
		http.Error(w, `{"error":"missing X-Agent-Id"}`, http.StatusBadRequest)
		return
	}

	tenantID, err := validateAgentIDTenant(agentID)
	if err != nil {
		http.Error(w, `{"error":"invalid agent_id format"}`, http.StatusBadRequest)
		return
	}
	// 高頻度経路。毎リクエストの TOML 4 連 DecodeFile + Glob を避け、
	// プロセス内キャッシュ（tenantID→*AppConfig）を参照する。設定変更時は SIGHUP で
	// config.ReloadConfigCache() が呼ばれキャッシュが破棄される。
	cfg, err := agentReportConfigForTenant(tenantID)
	if err != nil {
		log.Printf("ERROR: agent_report: config load error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if err := checkAgentIP(agentID, realIP(r), cfg); err != nil {
		log.Printf("WARN: agent_report: IP not allowed agent=%s: %v", agentID, err)
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}
	// 実 TCP 接続元（RemoteAddr）でも allowed_ips を再検証する。:8765 へ nginx を迂回して直結された場合に
	// X-Real-IP 偽装で allowlist を突破されるのを多層防御で防ぐ。
	// 正規経路（nginx → loopback プロキシ）では RemoteAddr が loopback になるため
	// この再検証はスキップし、trustedProxy 経由の realIP 判定に委ねる。
	if rh := agentRemoteAddrHost(r); rh != "" && !isLoopbackHost(rh) {
		if err := checkAgentIP(agentID, rh, cfg); err != nil {
			log.Printf("WARN: agent_report: RemoteAddr not allowed agent=%s remote=%s: %v", agentID, rh, err)
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
	}

	// ボディを先読みして署名検証＋JSONデコード両方に使う
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"body read error"}`, http.StatusBadRequest)
		return
	}

	// HMAC 検証
	if err := verifyAgentHMAC(r.Header, bodyBytes, agentID, cfg); err != nil {
		log.Printf("ERROR: agent_report: HMAC verify failed agent=%s: %v", agentID, err)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	jwtProvided := strings.HasPrefix(authHeader, "Bearer ")
	if jwtProvided {
		jwtToken := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if err := verifyAgentReportJWT(jwtToken, agentID, tenantID, cfg); err != nil {
			log.Printf("ERROR: agent_report: JWT verify failed agent=%s: %v", agentID, err)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
	} else if agentReportStrict(cfg) {
		log.Printf("WARN: agent_report: strict license rejected agent=%s: missing bearer token", agentID)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var report AgentReport
	if err := json.Unmarshal(bodyBytes, &report); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	if report.AgentID != agentID {
		http.Error(w, `{"error":"agent_id mismatch"}`, http.StatusBadRequest)
		return
	}

	now := time.Now().In(heartdesk.JST())
	record := agentReportRecord{
		ReceivedAt: now.Format(time.RFC3339),
		AgentID:    report.AgentID,
		AgentLabel: report.AgentLabel,
		// 報告の agent_type は "vps" / "rental" に正規化する。空・未知の値は "" とし、
		// 保存済みの種類を空で上書きしない（updateAgentLastSeenFields / UpsertAgent 側で保持）。
		AgentType:  config.NormalizeAgentType(report.AgentType),
		ReportedAt: report.ReportedAt,
		Collectors: report.Collectors,
	}
	if want := cfg.EffectiveAgentType(agentID, ""); want != "" && record.AgentType != "" && record.AgentType != want {
		if prev := GetAgentLastSeenByID(agentID); prev == nil || prev.AgentType != record.AgentType {
			log.Printf("WARN: agent_report: agent_type mismatch agent=%s config=%s reported=%s (config wins)", agentID, want, record.AgentType)
		}
	}

	if _, _, _, ok := currentAgentReportStores(); ok {
		if err := saveAgentReportSQLite(r.Context(), tenantID, record); err != nil {
			log.Printf("ERROR: agent_report: sqlite save error agent=%s: %v", agentID, err)
			http.Error(w, `{"error":"save failed"}`, http.StatusInternalServerError)
			return
		}
	} else {
		if err := saveAgentReport(record, cfg.AgentReport.RetentionMonths); err != nil {
			log.Printf("ERROR: agent_report: save error agent=%s: %v", agentID, err)
			http.Error(w, `{"error":"save failed"}`, http.StatusInternalServerError)
			return
		}
	}

	// 正本保存成功時点で last_seen を更新する。
	// event/audit 等の副次処理失敗で 500 になっても UI 上オフラインにならないようにする。
	updateAgentLastSeen(record, cfg)

	if err := saveAgentEventStreams(record); err != nil {
		log.Printf("ERROR: agent_report: event save error agent=%s: %v", agentID, err)
		http.Error(w, `{"error":"event save failed"}`, http.StatusInternalServerError)
		return
	}

	// collector_id="audit_log" を集約 SQLite に INSERT（Vendor Console の受信基盤）。
	// audit_aggregated が有効な集約役の Monitor のみ動作する。書き込み失敗は HTTP 500 を返し
	// Agent 側リトライで吸収させる。
	if err := insertAuditLogIfPresent(agentID, report.Collectors); err != nil {
		log.Printf("ERROR: agent_report: audit_aggregated insert failed agent=%s: %v", agentID, err)
		http.Error(w, `{"error":"audit aggregated insert failed"}`, http.StatusInternalServerError)
		return
	}

	AfterAgentReportSaved(cfg, report)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// insertAuditLogIfPresent は collectors["audit_log"] が含まれていれば集約 SQLite に INSERT する。
// audit_aggregated が無効な場合は no-op（集約役ではない Monitor 等）。
// payload 形式: {"new_events": N, "events": [audit.Event, ...]}（audit_log_tail collector 規定）。
func insertAuditLogIfPresent(agentID string, collectors map[string]json.RawMessage) error {
	if !auditdb.Enabled() {
		return nil
	}
	raw, ok := collectors["audit_log"]
	if !ok || len(raw) == 0 {
		return nil
	}
	var payload struct {
		Events []audit.Event `json:"events"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		// 配列直送りされた古い・代替フォーマットも一応許容する
		var events []audit.Event
		if err2 := json.Unmarshal(raw, &events); err2 != nil {
			return fmt.Errorf("decode audit_log payload: %w", err)
		}
		payload.Events = events
	}
	if len(payload.Events) == 0 {
		return nil
	}
	inserted, err := auditdb.InsertEvents(agentID, payload.Events)
	if err != nil {
		return err
	}
	if inserted > 0 {
		log.Printf("INFO: agent_report: audit_aggregated inserted agent=%s count=%d", agentID, inserted)
	}
	return nil
}

// verifyAgentHMAC は X-Agent-Timestamp / X-Agent-Signature ヘッダーを検証する。
// 候補キーは [agent_keys][agent_id]（local 用）と [aggregator_agent_keys][agent_id]（aggregator 用）の
// 順に試す。別テナントの Agent から集約 Monitor へ aggregator 経路で送られた report は
// 後者でのみ検証通過する。両方未設定なら未知 Agent として弾く。
func verifyAgentHMAC(header http.Header, body []byte, agentID string, cfg *config.AppConfig) error {
	if _, err := validateAgentIDTenant(agentID); err != nil {
		return err
	}

	tsStr := strings.TrimSpace(header.Get("X-Agent-Timestamp"))
	sig := strings.TrimSpace(header.Get("X-Agent-Signature"))
	if tsStr == "" || sig == "" {
		return fmt.Errorf("missing HMAC headers")
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp")
	}

	skew := cfg.AgentReport.TimestampSkewSec
	if skew <= 0 {
		skew = 120
	}
	diff := time.Now().Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(skew) {
		return fmt.Errorf("timestamp out of range: diff=%ds", diff)
	}

	var candidates []string
	if cfg.AgentKeys != nil {
		if k := cfg.AgentKeys[agentID]; k != "" {
			candidates = append(candidates, k)
		}
	}
	if cfg.AggregatorAgentKeys != nil {
		if k := cfg.AggregatorAgentKeys[agentID]; k != "" {
			candidates = append(candidates, k)
		}
	}
	if len(candidates) == 0 {
		return fmt.Errorf("unknown agent_id: %s", agentID)
	}

	for _, key := range candidates {
		// 署名計算を agentsig へ一元化（reporter 側と同一実装を共有）。
		if agentsig.Verify(key, tsStr, body, sig) {
			return nil
		}
	}
	return fmt.Errorf("signature mismatch")
}

func saveAgentReportSQLite(ctx context.Context, tenantID string, record agentReportRecord) error {
	tenantStore, agentStore, reportStore, ok := currentAgentReportStores()
	if !ok {
		return fmt.Errorf("agent report SQLite stores are not configured")
	}
	if err := ensureAgentReportTenant(ctx, tenantStore, tenantID); err != nil {
		return err
	}

	receivedAt, err := time.Parse(time.RFC3339, record.ReceivedAt)
	if err != nil {
		return fmt.Errorf("parse received_at: %w", err)
	}
	reportedAt := receivedAt
	if strings.TrimSpace(record.ReportedAt) != "" {
		if t, err := time.Parse(time.RFC3339, record.ReportedAt); err == nil {
			reportedAt = t
		}
	}
	collectorsJSON, err := json.Marshal(record.Collectors)
	if err != nil {
		return fmt.Errorf("marshal collectors: %w", err)
	}

	if err := agentStore.UpsertAgent(ctx, tenantID, store.Agent{
		TenantID:       tenantID,
		AgentID:        record.AgentID,
		AgentLabel:     record.AgentLabel,
		AgentType:      record.AgentType,
		LastReceivedAt: &receivedAt,
	}); err != nil {
		return err
	}

	raw := store.RawReport{
		TenantID:       tenantID,
		AgentID:        record.AgentID,
		ReceivedAt:     receivedAt,
		ReportedAt:     reportedAt,
		CollectorsJSON: string(collectorsJSON),
	}
	if err := reportStore.InsertRawReport(ctx, tenantID, raw); err != nil {
		return err
	}
	return nil
}

func ensureAgentReportTenant(ctx context.Context, tenantStore store.TenantStore, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("empty tenant_id")
	}
	existing, err := tenantStore.GetTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if existing != nil {
		return nil
	}
	if err := tenantStore.CreateTenant(ctx, store.Tenant{
		ID:   tenantID,
		Name: tenantID,
		Type: "monitor_owned",
	}); err != nil {
		return err
	}
	return nil
}

func verifyAgentReportJWT(jwtToken, agentID, tenantID string, cfg *config.AppConfig) error {
	if jwtToken == "" {
		return fmt.Errorf("empty bearer token")
	}

	unverifiedClaims, err := license.ExtractClaimsUnverified(jwtToken)
	if err != nil {
		return err
	}
	if isJTIRevoked(unverifiedClaims.JTI) {
		return fmt.Errorf("token revoked")
	}

	resolver, err := vendorPublicKeyResolver(cfg)
	if err != nil {
		return err
	}
	claims, err := license.VerifyJWT(jwtToken, resolver)
	if err != nil {
		return err
	}
	return validateAgentSessionClaims(claims, agentID, tenantID)
}

func isJTIRevoked(jti string) bool {
	if jti == "" {
		return false
	}
	jtiMu.Lock()
	defer jtiMu.Unlock()

	entry, ok := revokedJTIs[jti]
	if !ok {
		return false
	}
	if revokedEntryExpired(entry, time.Now()) {
		delete(revokedJTIs, jti)
		if err := persistRevokedJTIStoreLocked(); err != nil {
			log.Printf("ERROR: agent_report: cleanup expired revoked JTI failed jti=%s: %v", jti, err)
		}
		return false
	}
	return true
}

func vendorPublicKeyResolver(cfg *config.AppConfig) (func(kid string) (ed25519.PublicKey, bool), error) {
	keys := make(map[string]ed25519.PublicKey)
	for kid, entry := range cfg.VendorLicense.SigningKeys {
		if entry.PublicKeyB64 == "" {
			continue
		}
		pubKey, err := license.ParsePublicKey(entry.PublicKeyB64)
		if err != nil {
			return nil, fmt.Errorf("decode public key %q: %w", kid, err)
		}
		keys[kid] = pubKey
	}
	if len(keys) == 0 {
		return nil, errors.New("no vendor public keys configured")
	}
	return func(kid string) (ed25519.PublicKey, bool) {
		key, ok := keys[kid]
		return key, ok
	}, nil
}

// saveAgentReport はレポートをJSONLファイルに追記する
func saveAgentReport(record agentReportRecord, retentionMonths int) error {
	dir := agentReportDirPath()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	now := time.Now()
	ym := now.Format("200601")
	fpath := filepath.Join(dir, fmt.Sprintf("report_%s_%s.jsonl", record.AgentID, ym))

	// レポート JSONL は heartdesk プロセス専用のため 0600。
	f, err := os.OpenFile(fpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(record); err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	if retentionMonths > 0 {
		cleanOldAgentReports(dir, record.AgentID, retentionMonths, now)
	}
	return nil
}

func cleanOldAgentReports(dir, agentID string, retentionMonths int, now time.Time) {
	cutoff := now.AddDate(0, -retentionMonths, 0)
	pattern := filepath.Join(dir, fmt.Sprintf("report_%s_*.jsonl", agentID))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	for _, f := range matches {
		base := filepath.Base(f)
		// "report_<agentID>_YYYYMM.jsonl" → 末尾の YYYYMM を取得
		trimmed := strings.TrimSuffix(base, ".jsonl")
		idx := strings.LastIndex(trimmed, "_")
		if idx < 0 {
			continue
		}
		ym := trimmed[idx+1:]
		if len(ym) != 6 {
			continue
		}
		t, err := time.Parse("200601", ym)
		if err != nil {
			continue
		}
		if t.Before(cutoff) {
			_ = os.Remove(f)
		}
	}
}

func updateAgentLastSeen(record agentReportRecord, cfg *config.AppConfig) {
	updateAgentLastSeenFields(record.AgentID, record.AgentLabel, record.AgentType, record.ReceivedAt, record.Collectors)
}

func updateAgentLastSeenFields(agentID, agentLabel, agentType, receivedAt string, collectors map[string]json.RawMessage) {
	agentLastSeenMu.Lock()
	defer agentLastSeenMu.Unlock()
	if agentType == "" {
		// 種類の無い報告で、以前に受けた種類を消さない。
		if prev := agentLastSeen[agentID]; prev != nil {
			agentType = prev.AgentType
		}
	}
	agentLastSeen[agentID] = &AgentLastSeen{
		AgentID:    agentID,
		AgentLabel: agentLabel,
		AgentType:  agentType,
		ReceivedAt: receivedAt,
	}
	if len(collectors) > 0 {
		// Agent は系統別（resource/security/log/infra）に独立してレポートを送るため、
		// 1 レポートには一部の collector しか含まれない。キー単位でマージして保持する。
		existing := agentLatestCollectors[agentID]
		if existing == nil {
			existing = make(map[string]json.RawMessage, len(collectors))
		}
		for k, v := range collectors {
			existing[k] = v
		}
		agentLatestCollectors[agentID] = existing
	}
}

// GetAgentLatestCollector は指定 agentID の最新レポートに含まれる collector raw を返す。
// 受信実績がない / 該当 collector が含まれない場合は (nil, false)。
func GetAgentLatestCollector(agentID, collectorName string) (json.RawMessage, bool) {
	agentLastSeenMu.RLock()
	defer agentLastSeenMu.RUnlock()
	cols, ok := agentLatestCollectors[agentID]
	if !ok {
		return nil, false
	}
	raw, ok := cols[collectorName]
	if !ok {
		return nil, false
	}
	return raw, true
}

// RestoreAgentLastSeen は起動時に agent_reports/*.jsonl の最終行を読み込んで agentLastSeen を復元する
func RestoreAgentLastSeen() {
	if restoreAgentLastSeenFromSQLite(context.Background()) {
		return
	}
	restoreAgentLastSeenFromJSONL()
}

// restoreSQLiteMergeLimit は起動 restore 時に agent ごとにマージする直近レポート件数。
// Agent は系統別に分割送信するため、1 件だけだと collector が欠落する。
const restoreSQLiteMergeLimit = 50

func restoreAgentLastSeenFromSQLite(ctx context.Context) bool {
	_, agentStore, reportStore, ok := currentAgentReportStores()
	if !ok {
		return false
	}
	agents, err := agentStore.GetAgentsAcrossTenants(ctx)
	if err != nil {
		log.Printf("ERROR: RestoreAgentLastSeen: sqlite restore failed: %v", err)
		return false
	}
	if len(agents) == 0 {
		return false
	}
	to := time.Now().Add(latestReportFutureBuffer)
	for _, agent := range agents {
		if agent.LastReceivedAt == nil {
			continue
		}
		receivedAt := agent.LastReceivedAt.In(heartdesk.JST()).Format(time.RFC3339)
		collectors := map[string]json.RawMessage{}
		// 直近 N 件を古い→新しい順にマージ（JSONL restore と同思想）。
		reports, err := reportStore.ListRawReports(ctx, agent.TenantID, agent.AgentID, time.Unix(0, 0), to, restoreSQLiteMergeLimit)
		if err != nil {
			log.Printf("ERROR: RestoreAgentLastSeen: sqlite list reports agent=%s: %v", agent.AgentID, err)
		} else if len(reports) > 0 {
			// ListRawReports は新しい順（limit 先頭が最新）想定のため、末尾から古い方へ辿る。
			for i := len(reports) - 1; i >= 0; i-- {
				raw := reports[i]
				if strings.TrimSpace(raw.CollectorsJSON) == "" {
					continue
				}
				var cols map[string]json.RawMessage
				if err := json.Unmarshal([]byte(raw.CollectorsJSON), &cols); err != nil {
					continue
				}
				for k, v := range cols {
					collectors[k] = v
				}
			}
			// 最新行の ReceivedAt を採用
			if !reports[0].ReceivedAt.IsZero() {
				receivedAt = reports[0].ReceivedAt.In(heartdesk.JST()).Format(time.RFC3339)
			}
		}
		updateAgentLastSeenFields(agent.AgentID, agent.AgentLabel, agent.AgentType, receivedAt, collectors)
	}
	return true
}

func restoreAgentLastSeenFromJSONL() {
	dir := agentReportDirPath()
	matches, err := filepath.Glob(filepath.Join(dir, "report_*_*.jsonl"))
	if err != nil || len(matches) == 0 {
		return
	}
	for _, fpath := range matches {
		expectedID := agentIDFromReportFilename(filepath.Base(fpath))
		// 直近 200 行を読み取り、コレクターをキー単位でマージ（低頻度コレクター再起動後消失防止）
		lines, err := tailLines(fpath, 200)
		if err != nil || len(lines) == 0 {
			continue
		}
		// 古い→新しい順に処理して最新値を上書きする
		var latestRec *agentReportRecord
		mergedCols := make(map[string]json.RawMessage)
		for _, line := range lines {
			if len(line) == 0 {
				continue
			}
			var rec agentReportRecord
			if err := json.Unmarshal(line, &rec); err != nil || rec.AgentID == "" {
				continue
			}
			if expectedID != "" && rec.AgentID != expectedID {
				continue
			}
			if latestRec == nil || rec.ReceivedAt > latestRec.ReceivedAt {
				latestRec = &rec
			}
			for k, v := range rec.Collectors {
				mergedCols[k] = v
			}
		}
		if latestRec == nil {
			continue
		}
		agentLastSeenMu.Lock()
		existing := agentLastSeen[latestRec.AgentID]
		if existing == nil || latestRec.ReceivedAt > existing.ReceivedAt {
			agentLastSeen[latestRec.AgentID] = &AgentLastSeen{
				AgentID:    latestRec.AgentID,
				AgentLabel: latestRec.AgentLabel,
				AgentType:  latestRec.AgentType,
				ReceivedAt: latestRec.ReceivedAt,
			}
		}
		if len(mergedCols) > 0 {
			existing := agentLatestCollectors[latestRec.AgentID]
			if existing == nil {
				existing = make(map[string]json.RawMessage, len(mergedCols))
			}
			for k, v := range mergedCols {
				existing[k] = v
			}
			agentLatestCollectors[latestRec.AgentID] = existing
		}
		agentLastSeenMu.Unlock()
	}
}

// tailLines はファイル末尾から最大 n 行を古い順で返す。
// 大きなファイルでも末尾チャンクのみ読み取る（最大 512KB）。
func tailLines(path string, n int) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	const maxRead = 512 * 1024
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	offset := size - maxRead
	if offset < 0 {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	// offset > 0 の場合は先頭が途中から始まるので最初の改行まで捨てる
	if offset > 0 {
		idx := bytes.IndexByte(buf, '\n')
		if idx >= 0 {
			buf = buf[idx+1:]
		}
	}
	all := bytes.Split(buf, []byte("\n"))
	// 空行除去
	var nonempty [][]byte
	for _, l := range all {
		if len(bytes.TrimSpace(l)) > 0 {
			nonempty = append(nonempty, l)
		}
	}
	if len(nonempty) <= n {
		return nonempty, nil
	}
	return nonempty[len(nonempty)-n:], nil
}

// lastLine はファイルの最終（非空）行を返す。
// 先頭からの全読みを避け、末尾からチャンク単位で逆方向に読んで最初に
// 見つかった改行以降を最終行として返す（loadLatestAgentRecord から頻繁に呼ばれる）。
func lastLine(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	if size == 0 {
		return nil, nil
	}

	const chunk = 4096
	var buf []byte // 末尾から読んだバイト列（前方向に連結していく）
	offset := size
	for offset > 0 {
		readSize := int64(chunk)
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize
		tmp := make([]byte, readSize)
		if _, err := f.ReadAt(tmp, offset); err != nil && err != io.EOF {
			return nil, err
		}
		buf = append(tmp, buf...)
		// 末尾の改行を除いた範囲に改行があれば、その後ろが最終非空行
		trimmed := bytes.TrimRight(buf, "\n")
		if idx := bytes.LastIndexByte(trimmed, '\n'); idx >= 0 {
			return trimmed[idx+1:], nil
		}
	}
	// ファイル全体が1行（または末尾改行のみ）
	return bytes.TrimRight(buf, "\n"), nil
}

// GetAgentStatus は全Agentの死活状況を返す（Monitor画面のAPI用）
func GetAgentStatus() []AgentLastSeen {
	// 起動時ロード済みキャッシュを参照する。
	cfg, err := config.CachedAppConfigForTenant("")
	if err != nil {
		cfg = &config.AppConfig{}
	}
	return GetAgentStatusForConfig(cfg)
}

// GetAgentStatusForConfig は指定設定で管理対象のAgent死活状況を返す。
func GetAgentStatusForConfig(cfg *config.AppConfig) []AgentLastSeen {
	agentLastSeenMu.RLock()
	defer agentLastSeenMu.RUnlock()

	now := time.Now().In(heartdesk.JST())
	result := make([]AgentLastSeen, 0, len(agentLastSeen))
	seenIDs := make(map[string]struct{}, len(agentLastSeen))
	for _, seen := range agentLastSeen {
		if cfg != nil && len(cfg.Agents) > 0 {
			if _, ok := cfg.Agents[seen.AgentID]; !ok {
				continue
			}
		}
		seenIDs[seen.AgentID] = struct{}{}
		effType := cfg.EffectiveAgentType(seen.AgentID, seen.AgentType)
		t, parseErr := time.Parse(time.RFC3339, seen.ReceivedAt)
		// パース失敗は健全扱いにせずアラートにする。
		minutesAgo := 0
		isAlert := false
		displayAt := seen.ReceivedAt
		if parseErr != nil || t.IsZero() {
			isAlert = true
		} else {
			minutesAgo = int(now.Sub(t).Minutes())
			alertMin := alertThresholdMin(effType, cfg)
			isAlert = minutesAgo >= alertMin
			displayAt = heartdesk.FormatDatetime(t.In(heartdesk.JST()))
		}
		displayLabel := resolveAgentDisplayLabel(cfg, seen.AgentID, seen.AgentLabel)
		result = append(result, AgentLastSeen{
			AgentID:           seen.AgentID,
			AgentLabel:        displayLabel,
			AgentType:         effType,
			ReceivedAt:        seen.ReceivedAt,
			ReceivedAtDisplay: displayAt,
			MinutesAgo:        minutesAgo,
			IsAlert:           isAlert,
		})
	}

	// config 定義済みだが未報告の agent を overview と同様にアラート行として追加。
	if cfg != nil {
		for agentID, agentCfg := range cfg.Agents {
			if _, ok := seenIDs[agentID]; ok {
				continue
			}
			label := agentCfg.AgentLabel
			if label == "" {
				label = agentID
			}
			result = append(result, AgentLastSeen{
				AgentID:           agentID,
				AgentLabel:        label,
				AgentType:         agentCfg.AgentType,
				ReceivedAt:        "",
				ReceivedAtDisplay: "",
				MinutesAgo:        0,
				IsAlert:           true,
			})
		}
	}
	return result
}

// alertThresholdMin は agent の種類（cfg.EffectiveAgentType で決めた値）に応じた無報告アラート閾値（分）を返す。
func alertThresholdMin(agentType string, cfg *config.AppConfig) int {
	if cfg == nil {
		cfg = &config.AppConfig{}
	}
	switch config.NormalizeAgentType(agentType) {
	case "rental":
		if cfg.AgentHealth.RentalAlertMin > 0 {
			return cfg.AgentHealth.RentalAlertMin
		}
		return 10
	default:
		if cfg.AgentHealth.VPSAlertMin > 0 {
			return cfg.AgentHealth.VPSAlertMin
		}
		return 5
	}
}

func resolveAgentDisplayLabel(cfg *config.AppConfig, agentID, fallback string) string {
	if cfg != nil && cfg.Agents != nil {
		if agentCfg, ok := cfg.Agents[agentID]; ok {
			if label := strings.TrimSpace(agentCfg.AgentLabel); label != "" {
				return label
			}
		}
	}
	return fallback
}

// AgentOverviewItem は全サーバー概要画面の1 Agent カードデータ
type AgentOverviewItem struct {
	AgentID    string  `json:"agent_id"`
	AgentLabel string  `json:"agent_label"`
	AgentType  string  `json:"agent_type"`
	AgentIP    string  `json:"agent_ip,omitempty"`
	IsPrimary  bool    `json:"is_primary"`
	ReceivedAt string  `json:"received_at"`
	MinutesAgo int     `json:"minutes_ago"`
	IsAlert    bool    `json:"is_alert"`
	CPUPct     float64 `json:"cpu_pct"`
	MemPct     float64 `json:"mem_pct"`
	MemTotal   string  `json:"mem_total"`
	DiskPct    string  `json:"disk_pct"` // "38%" 形式。取得不可時は ""
	DiskTotal  string  `json:"disk_total"`
	BanActive  int     `json:"ban_active"`
	HasData    bool    `json:"has_data"` // false = 受信実績なし
}

type agentOverviewMetrics struct {
	CPUPct    float64
	MemPct    float64
	MemTotal  string
	DiskPct   string
	DiskTotal string
	BanActive int
	HasData   bool
}

// GetAgentLastSeenByID は指定 agent_id の AgentLastSeen を返す。見つからない場合は nil。
func GetAgentLastSeenByID(agentID string) *AgentLastSeen {
	agentLastSeenMu.RLock()
	defer agentLastSeenMu.RUnlock()
	seen, ok := agentLastSeen[agentID]
	if !ok {
		return nil
	}
	cp := *seen
	return &cp
}

// GetAgentOverview は全 Agent のサマリーを返す（vendor 向け・フィルタなし）。
// Monitor 画面・tenant API は GetAgentOverviewForSession / agentOverviewForRequest を使うこと。
func GetAgentOverview() []AgentOverviewItem {
	return GetAgentOverviewForSession(string(auth.RoleVendorStaff), "")
}

// agentOverviewForRequest はセッションの role/tenant でフィルタした overview を返す。
func agentOverviewForRequest(r *http.Request) []AgentOverviewItem {
	sess, ok := auth.DefaultSessionManager().SessionFromRequest(r)
	if !ok {
		return nil
	}
	return GetAgentOverviewForSession(sess.Role, sess.TenantID)
}

// GetAgentOverviewForSession はセッション role/tenant に応じて Agent サマリーを返す。
// vendor_staff 以外は sess.TenantID と agent の tenant prefix が一致するものだけ。
func GetAgentOverviewForSession(role, tenantID string) []AgentOverviewItem {
	// 起動時ロード済みキャッシュを参照する。
	cfg, err := config.CachedAppConfigForTenant("")
	if err != nil {
		cfg = &config.AppConfig{}
	}

	agentLastSeenMu.RLock()
	seenCopy := make(map[string]*AgentLastSeen, len(agentLastSeen))
	for k, v := range agentLastSeen {
		seenCopy[k] = v
	}
	collectorsCopy := make(map[string]map[string]json.RawMessage, len(agentLatestCollectors))
	for k, cols := range agentLatestCollectors {
		cp := make(map[string]json.RawMessage, len(cols))
		for ck, cv := range cols {
			cp[ck] = cv
		}
		collectorsCopy[k] = cp
	}
	agentLastSeenMu.RUnlock()

	now := time.Now().In(heartdesk.JST())
	result := make([]AgentOverviewItem, 0, len(seenCopy))
	vendorAll := auth.Role(auth.NormalizeRole(role)) == auth.RoleVendorStaff
	sessTenant := strings.TrimSpace(tenantID)

	for _, seen := range seenCopy {
		if !vendorAll {
			if sessTenant == "" || tenantIDFromAgentID(seen.AgentID) != sessTenant {
				continue
			}
		}
		effType := cfg.EffectiveAgentType(seen.AgentID, seen.AgentType)
		t, parseErr := time.Parse(time.RFC3339, seen.ReceivedAt)
		// パース失敗は minutesAgo=0 の健全扱いせずアラートにする。
		minutesAgo := 0
		isAlert := false
		if parseErr != nil || t.IsZero() {
			isAlert = true
		} else {
			minutesAgo = int(now.Sub(t).Minutes())
			alertMin := alertThresholdMin(effType, cfg)
			isAlert = minutesAgo >= alertMin
		}

		isPrimary := false
		if cfg != nil {
			if agentCfg, ok := cfg.Agents[seen.AgentID]; ok {
				isPrimary = agentCfg.IsPrimary
			}
		}

		displayLabel := resolveAgentDisplayLabel(cfg, seen.AgentID, seen.AgentLabel)
		item := AgentOverviewItem{
			AgentID:    seen.AgentID,
			AgentLabel: displayLabel,
			AgentType:  effType,
			AgentIP:    resolveAgentDisplayIP(cfg, seen.AgentID),
			IsPrimary:  isPrimary,
			ReceivedAt: seen.ReceivedAt,
			MinutesAgo: minutesAgo,
			IsAlert:    isAlert,
			HasData:    false,
		}

		// マージ済み collectors を優先（部分レポート対策）。無ければディスク最新 1 件。
		if cols := collectorsCopy[seen.AgentID]; len(cols) > 0 {
			metrics := extractAgentOverviewMetrics(&agentReportRecord{Collectors: cols})
			item.HasData = metrics.HasData
			item.CPUPct = metrics.CPUPct
			item.MemPct = metrics.MemPct
			item.MemTotal = metrics.MemTotal
			item.DiskPct = metrics.DiskPct
			item.DiskTotal = metrics.DiskTotal
			item.BanActive = metrics.BanActive
		} else if rec := loadLatestAgentRecord(seen.AgentID); rec != nil {
			metrics := extractAgentOverviewMetrics(rec)
			item.HasData = metrics.HasData
			item.CPUPct = metrics.CPUPct
			item.MemPct = metrics.MemPct
			item.MemTotal = metrics.MemTotal
			item.DiskPct = metrics.DiskPct
			item.DiskTotal = metrics.DiskTotal
			item.BanActive = metrics.BanActive
		}

		result = append(result, item)
	}

	// config に定義済みだが一度も報告していないエージェントを追加
	if cfg != nil {
		seenIDs := make(map[string]struct{}, len(result))
		for _, item := range result {
			seenIDs[item.AgentID] = struct{}{}
		}
		for agentID, agentCfg := range cfg.Agents {
			if _, ok := seenIDs[agentID]; ok {
				continue
			}
			if !vendorAll {
				if sessTenant == "" || tenantIDFromAgentID(agentID) != sessTenant {
					continue
				}
			}
			label := agentCfg.AgentLabel
			if label == "" {
				label = agentID
			}
			result = append(result, AgentOverviewItem{
				AgentID:    agentID,
				AgentLabel: label,
				AgentType:  agentCfg.AgentType,
				AgentIP:    agentCfg.AgentIP,
				IsPrimary:  agentCfg.IsPrimary,
				ReceivedAt: "",
				MinutesAgo: 0,
				IsAlert:    true,
				HasData:    false,
			})
		}
	}

	// Main Server（is_primary）を先頭に、残りは AgentID 辞書順
	for i := 1; i < len(result); i++ {
		for j := i; j > 0; j-- {
			a, b := result[j-1], result[j]
			swap := false
			if !a.IsPrimary && b.IsPrimary {
				swap = true
			} else if a.IsPrimary == b.IsPrimary && a.AgentID > b.AgentID {
				swap = true
			}
			if !swap {
				break
			}
			result[j-1], result[j] = result[j], result[j-1]
		}
	}
	return result
}

func resolveAgentDisplayIP(cfg *config.AppConfig, agentID string) string {
	if cfg == nil || len(cfg.Agents) == 0 || agentID == "" {
		return ""
	}
	if agentCfg, ok := cfg.Agents[agentID]; ok {
		return strings.TrimSpace(agentCfg.AgentIP)
	}
	trimmedID := strings.TrimSpace(agentID)
	for id, agentCfg := range cfg.Agents {
		if strings.HasSuffix(id, trimmedID) || strings.HasSuffix(trimmedID, id) {
			return strings.TrimSpace(agentCfg.AgentIP)
		}
	}
	return ""
}

func extractAgentOverviewMetrics(rec *agentReportRecord) agentOverviewMetrics {
	if rec == nil {
		return agentOverviewMetrics{}
	}

	out := agentOverviewMetrics{
		BanActive: extractBanActive(rec.Collectors["fail2ban"]),
	}

	// 現行 VPS agent は system collector に CPU/Memory/Disk を内包する。
	if raw := rec.Collectors["system"]; raw != nil {
		if sys, ok := decodeSystemCollectorResult(raw); ok {
			out.CPUPct = sys.CPU.UsagePercent
			out.MemPct = sys.Memory.UsagePercent
			if sys.Memory.TotalKB > 0 {
				out.MemTotal = humanBytesReport(sys.Memory.TotalKB * 1024)
			}
			out.DiskPct = rootDiskPercent(sys.Disk)
			out.DiskTotal = rootDiskTotal(sys.Disk)
			out.HasData = true
			return out
		}

		// 旧レポート形式との後方互換
		out.CPUPct = extractFloat(raw, "cpu_pct")
		out.MemPct = extractFloat(raw, "mem_pct")
		out.DiskPct = extractString(raw, "disk_pct")
		out.HasData = true
		return out
	}

	// rental agent は collector が cpu / memory / disk に分かれている。
	if raw := rec.Collectors["cpu"]; raw != nil {
		out.CPUPct = extractFloat(raw, "usage_percent")
		out.HasData = true
	}
	if raw := rec.Collectors["memory"]; raw != nil {
		// 現行 rental memory collector は総量のみで使用率は未送信。
		if v := extractFloat(raw, "usage_percent"); v > 0 {
			out.MemPct = v
		}
		if total := extractInt64(raw, "phys_mem_bytes"); total > 0 {
			out.MemTotal = humanBytesReport(total)
		}
		out.HasData = true
	}
	if raw := rec.Collectors["disk"]; raw != nil {
		if pct := extractRentalRootDiskPercent(raw); pct != "" {
			out.DiskPct = pct
		}
		if total := extractRentalRootDiskTotal(raw); total != "" {
			out.DiskTotal = total
		}
		out.HasData = true
	}

	return out
}

// loadLatestAgentRecord は agent_reports/ から最新月の最終レコードを返す
func loadLatestAgentRecord(agentID string) *agentReportRecord {
	// 呼び出し元がレガシー経路でも agent_id を fail-closed で検証する。
	if strings.TrimSpace(agentID) == "" || !isValidAgentID(agentID) {
		return nil
	}
	if tenantID := tenantIDFromAgentID(agentID); tenantID != "" {
		if rec := loadLatestAgentRecordFromSQLite(context.Background(), tenantID, agentID); rec != nil {
			return rec
		}
	}
	dir := agentReportDirPath()
	pattern := filepath.Join(dir, fmt.Sprintf("report_%s_*.jsonl", agentID))
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	// ファイル名降順（最新月が末尾）
	latest := matches[0]
	for _, m := range matches[1:] {
		if m > latest {
			latest = m
		}
	}
	line, err := lastLine(latest)
	if err != nil || len(line) == 0 {
		return nil
	}
	var rec agentReportRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		return nil
	}
	return &rec
}

// latestReportFutureBuffer は最新レポート取得時の終端時刻に足す未来方向の余裕。
// Agent とのクロックスキュー分だけ未来寄りのレポートも取りこぼさないための上限。
const latestReportFutureBuffer = 24 * time.Hour

func loadLatestAgentRecordFromSQLite(ctx context.Context, tenantID, agentID string) *agentReportRecord {
	_, agentStore, reportStore, ok := currentAgentReportStores()
	if !ok || tenantID == "" || agentID == "" {
		return nil
	}
	// 終端時刻は「現在 + 余裕」とする。Agent とのクロックスキューで僅かに未来の
	// タイムスタンプを持つレポートも最新1件取得から漏らさないための上限バッファ。
	to := time.Now().Add(latestReportFutureBuffer)
	reports, err := reportStore.ListRawReports(ctx, tenantID, agentID, time.Unix(0, 0), to, 1)
	if err != nil || len(reports) == 0 {
		if err != nil {
			log.Printf("ERROR: loadLatestAgentRecord: sqlite raw report error agent=%s: %v", agentID, err)
		}
		return nil
	}
	raw := reports[0]
	agent, err := agentStore.GetAgentByID(ctx, tenantID, agentID)
	if err != nil {
		log.Printf("ERROR: loadLatestAgentRecord: sqlite agent error agent=%s: %v", agentID, err)
	}
	label := ""
	agentType := ""
	if agent != nil {
		label = agent.AgentLabel
		agentType = agent.AgentType
	}
	collectors := map[string]json.RawMessage{}
	if strings.TrimSpace(raw.CollectorsJSON) != "" {
		if err := json.Unmarshal([]byte(raw.CollectorsJSON), &collectors); err != nil {
			log.Printf("ERROR: loadLatestAgentRecord: sqlite collectors decode error agent=%s: %v", agentID, err)
			collectors = map[string]json.RawMessage{}
		}
	}
	return &agentReportRecord{
		ReceivedAt: raw.ReceivedAt.In(heartdesk.JST()).Format(time.RFC3339),
		AgentID:    raw.AgentID,
		AgentLabel: label,
		AgentType:  agentType,
		ReportedAt: raw.ReportedAt.In(heartdesk.JST()).Format(time.RFC3339),
		Collectors: collectors,
	}
}

// extractField は json.RawMessage を map にデコードし key の値を型 T で取り出す汎用ヘルパ。
// extractFloat/String/Int64/BanActive で反復していた同型の `var m map[string]interface{}; json.Unmarshal(...)` を 1 関数に集約する。
// 取得不可 / 型不一致なら (zero, false) を返す。型付きデコードが正で、本ヘルパは弱い後方互換抽出用。
func extractField[T any](raw json.RawMessage, key string) (T, bool) {
	var zero T
	if raw == nil {
		return zero, false
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return zero, false
	}
	v, ok := m[key]
	if !ok {
		return zero, false
	}
	t, ok := v.(T)
	if !ok {
		return zero, false
	}
	return t, true
}

func extractFloat(raw json.RawMessage, key string) float64 {
	f, _ := extractField[float64](raw, key)
	return f
}

func extractString(raw json.RawMessage, key string) string {
	s, _ := extractField[string](raw, key)
	return s
}

func extractInt64(raw json.RawMessage, key string) int64 {
	f, _ := extractField[float64](raw, key)
	return int64(f)
}

func extractBanActive(raw json.RawMessage) int {
	// fail2ban collector の active フィールド（GetFail2ban の Fail2banData.Active 相当）
	f, _ := extractField[float64](raw, "active")
	return int(f)
}

// loadCollectorRaw は指定 agentID の collectorKey の RawMessage を返す。
// メモリ上のマージ済み collectors を優先し、無ければディスク最新 1 件へフォールバック。
// レポートが存在しない・コレクターが含まれない場合は nil を返す。
func loadCollectorRaw(agentID, collectorKey string) json.RawMessage {
	if raw, ok := GetAgentLatestCollector(agentID, collectorKey); ok && len(raw) > 0 {
		return raw
	}
	rec := loadLatestAgentRecord(agentID)
	if rec == nil {
		return nil
	}
	raw, ok := rec.Collectors[collectorKey]
	if !ok {
		return nil
	}
	return raw
}

// reportReceivedAt は agentID の最新レポート受信時刻を返す（JST フォーマット済み）。
func reportReceivedAt(agentID string) string {
	agentLastSeenMu.RLock()
	seen := agentLastSeen[agentID]
	agentLastSeenMu.RUnlock()
	if seen == nil {
		return ""
	}
	t, err := time.Parse(time.RFC3339, seen.ReceivedAt)
	if err != nil {
		return seen.ReceivedAt
	}
	return heartdesk.FormatDatetime(t.In(heartdesk.JST()))
}

// systemCollectorResult は system collector の JSON 構造
type systemCollectorResult struct {
	CPU struct {
		UsagePercent float64 `json:"usage_percent"`
	} `json:"cpu"`
	Memory struct {
		TotalKB      int64   `json:"total_kb"`
		AvailableKB  int64   `json:"available_kb"`
		UsedKB       int64   `json:"used_kb"`
		UsagePercent float64 `json:"usage_percent"`
	} `json:"memory"`
	Disk []struct {
		MountPoint   string  `json:"mount_point"`
		TotalKB      int64   `json:"total_kb"`
		UsedKB       int64   `json:"used_kb"`
		AvailableKB  int64   `json:"available_kb"`
		UsagePercent float64 `json:"usage_percent"`
	} `json:"disk"`
	Load struct {
		Load1  float64 `json:"load1"`
		Load5  float64 `json:"load5"`
		Load15 float64 `json:"load15"`
	} `json:"load"`
	Uptime struct {
		UptimeSeconds int64 `json:"uptime_seconds"`
	} `json:"uptime"`
	Swap struct {
		TotalKB      int64   `json:"total_kb"`
		FreeKB       int64   `json:"free_kb"`
		UsedKB       int64   `json:"used_kb"`
		UsagePercent float64 `json:"usage_percent"`
		SwapInPages  int64   `json:"swap_in_pages"`
		SwapOutPages int64   `json:"swap_out_pages"`
	} `json:"swap"`
	CPUTimes struct {
		UserPct    float64 `json:"user_pct"`
		NicePct    float64 `json:"nice_pct"`
		SystemPct  float64 `json:"system_pct"`
		IdlePct    float64 `json:"idle_pct"`
		IowaitPct  float64 `json:"iowait_pct"`
		IrqPct     float64 `json:"irq_pct"`
		SoftirqPct float64 `json:"softirq_pct"`
		StealPct   float64 `json:"steal_pct"`
	} `json:"cpu_times"`
	DiskIO []struct {
		Device       string `json:"device"`
		ReadIOs      int64  `json:"read_ios"`
		ReadSectors  int64  `json:"read_sectors"`
		ReadBytes    int64  `json:"read_bytes"`
		WriteIOs     int64  `json:"write_ios"`
		WriteSectors int64  `json:"write_sectors"`
		WriteBytes   int64  `json:"write_bytes"`
		InFlight     int64  `json:"in_flight"`
		IOMs         int64  `json:"io_ms"`
		WeightedIOMs int64  `json:"weighted_io_ms"`
	} `json:"disk_io"`
	OpenFiles struct {
		Allocated int64 `json:"allocated"`
		Unused    int64 `json:"unused"`
		Max       int64 `json:"max"`
		Used      int64 `json:"used"`
	} `json:"open_files"`
	NetworkErrors []struct {
		Interface string `json:"interface"`
		RxErrors  int64  `json:"rx_errors"`
		RxDropped int64  `json:"rx_dropped"`
		TxErrors  int64  `json:"tx_errors"`
		TxDropped int64  `json:"tx_dropped"`
	} `json:"network_errors"`
	NetworkIO []struct {
		Interface string `json:"interface"`
		RxBytes   int64  `json:"rx_bytes"`
		TxBytes   int64  `json:"tx_bytes"`
	} `json:"network_io"`
	Host struct {
		Hostname      string `json:"hostname"`
		OSName        string `json:"os_name"`
		OSVersion     string `json:"os_version"`
		OSPrettyName  string `json:"os_pretty_name"`
		KernelVersion string `json:"kernel_version"`
		CPUModel      string `json:"cpu_model"`
		CPUCores      int    `json:"cpu_cores"`
		RAMTotalKB    int64  `json:"ram_total_kb"`
	} `json:"host"`
}

type rentalCPUCollectorResult struct {
	UsagePercent float64 `json:"usage_percent"`
}

type rentalMemoryCollectorResult struct {
	PhysMemBytes int64 `json:"phys_mem_bytes"`
}

type rentalLoadavgCollectorResult struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

type rentalHostCollectorResult struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}

type rentalNetworkCollectorResult struct {
	TxBytes int64 `json:"tx_bytes"`
	RxBytes int64 `json:"rx_bytes"`
}

type rentalProcessCollectorEntry struct {
	PID     string `json:"pid"`
	CPU     string `json:"cpu"`
	Mem     string `json:"mem"`
	RSS     string `json:"rss"`
	Command string `json:"command"`
}

type backupCollectorResult struct {
	BackupFiles   []BackupFile `json:"backup_files"`
	NCBackupFiles []BackupFile `json:"nc_backup_files"`
	DBSize        string       `json:"db_size"`
	DBList        []DBInfo     `json:"db_list"`
}

type cloudflareCollectorResult struct {
	Storage    *cloudflareStorageInfo    `json:"storage"`
	Operations *cloudflareOperationsInfo `json:"operations"`
}

type cloudflareStorageInfo struct {
	PayloadSize string                             `json:"payload_size"`
	ObjectCount string                             `json:"object_count"`
	Buckets     map[string]cloudflareBucketInfoRaw `json:"buckets"`
}

type cloudflareBucketInfoRaw struct {
	PayloadSize string `json:"payload_size"`
	ObjectCount string `json:"object_count"`
}

type cloudflareOperationsInfo struct {
	ClassA int    `json:"class_a"`
	ClassB int    `json:"class_b"`
	Month  string `json:"month"`
}

func decodeSystemCollectorResult(raw json.RawMessage) (systemCollectorResult, bool) {
	var sys systemCollectorResult
	if raw == nil {
		return sys, false
	}
	if err := json.Unmarshal(raw, &sys); err != nil {
		return sys, false
	}
	return sys, true
}

func rootDiskPercent(disks []struct {
	MountPoint   string  `json:"mount_point"`
	TotalKB      int64   `json:"total_kb"`
	UsedKB       int64   `json:"used_kb"`
	AvailableKB  int64   `json:"available_kb"`
	UsagePercent float64 `json:"usage_percent"`
}) string {
	for _, disk := range disks {
		if disk.MountPoint == "/" {
			return fmt.Sprintf("%.0f%%", disk.UsagePercent)
		}
	}
	return ""
}

func rootDiskTotal(disks []struct {
	MountPoint   string  `json:"mount_point"`
	TotalKB      int64   `json:"total_kb"`
	UsedKB       int64   `json:"used_kb"`
	AvailableKB  int64   `json:"available_kb"`
	UsagePercent float64 `json:"usage_percent"`
}) string {
	for _, disk := range disks {
		if disk.MountPoint == "/" && disk.TotalKB > 0 {
			return humanBytesReport(disk.TotalKB * 1024)
		}
	}
	return ""
}

type rentalDiskOverviewEntry struct {
	Size       string `json:"size"`
	Used       string `json:"used"`
	Avail      string `json:"avail"`
	UsePercent string `json:"use_percent"`
	Mounted    string `json:"mounted"`
}

func extractRentalRootDiskPercent(raw json.RawMessage) string {
	if raw == nil {
		return ""
	}
	var disks []rentalDiskOverviewEntry
	if err := json.Unmarshal(raw, &disks); err != nil {
		return ""
	}
	for _, disk := range disks {
		if disk.Mounted == "/" {
			return disk.UsePercent
		}
	}
	return ""
}

func extractRentalRootDiskTotal(raw json.RawMessage) string {
	if raw == nil {
		return ""
	}
	var disks []rentalDiskOverviewEntry
	if err := json.Unmarshal(raw, &disks); err != nil {
		return ""
	}
	for _, disk := range disks {
		if disk.Mounted == "/" {
			return disk.Size
		}
	}
	return ""
}

// resourcesFromReport は agentID の最新 system collector から ResourcesData を生成する。
// コレクターが存在しない場合は Unavailable=true を返す。
func resourcesFromReport(agentID string) (ResourcesData, bool) {
	if d, ok := resourcesFromSystemReport(agentID); ok {
		return d, true
	}
	return resourcesFromRentalCollectors(agentID)
}

func resourcesFromSystemReport(agentID string) (ResourcesData, bool) {
	raw := loadCollectorRaw(agentID, "system")
	if raw == nil {
		return ResourcesData{}, false
	}
	var sys systemCollectorResult
	if err := json.Unmarshal(raw, &sys); err != nil {
		return ResourcesData{}, false
	}

	d := ResourcesData{
		UpdatedAt: reportReceivedAt(agentID),
		CPUPct:    sys.CPU.UsagePercent,
		Load1:     sys.Load.Load1,
		Load5:     sys.Load.Load5,
		Load15:    sys.Load.Load15,
		MemTotal:  sys.Memory.TotalKB * 1024,
		MemUsed:   sys.Memory.UsedKB * 1024,
		MemAvail:  sys.Memory.AvailableKB * 1024,
		MemPct:    sys.Memory.UsagePercent,
		SwapTotal: sys.Swap.TotalKB * 1024,
		SwapFree:  sys.Swap.FreeKB * 1024,
		CPUModel:  sys.Host.CPUModel,
		CPUCores:  sys.Host.CPUCores,
		OSLabel:   systemHostOSLabel(sys),
		Kernel:    sys.Host.KernelVersion,
	}
	ramBytes := sys.Host.RAMTotalKB * 1024
	if ramBytes <= 0 {
		ramBytes = sys.Memory.TotalKB * 1024
	}
	d.RAMTotal = humanGiB(ramBytes)

	// uptime を人間が読める形式に変換
	if sec := sys.Uptime.UptimeSeconds; sec > 0 {
		days := sec / 86400
		hours := (sec % 86400) / 3600
		mins := (sec % 3600) / 60
		if days > 0 {
			d.Uptime = fmt.Sprintf("up %d day(s), %02d:%02d", days, hours, mins)
		} else {
			d.Uptime = fmt.Sprintf("up %02d:%02d", hours, mins)
		}
	}

	// ルートディスク（/）を探す
	for _, disk := range sys.Disk {
		if disk.MountPoint == "/" {
			totalBytes := disk.TotalKB * 1024
			usedBytes := disk.UsedKB * 1024
			freeBytes := disk.AvailableKB * 1024
			d.DiskTotal = humanBytesReport(totalBytes)
			d.DiskUsed = humanBytesReport(usedBytes)
			d.DiskFree = humanBytesReport(freeBytes)
			d.DiskPct = fmt.Sprintf("%.0f%%", disk.UsagePercent)
			break
		}
	}

	return d, true
}

func resourcesFromRentalCollectors(agentID string) (ResourcesData, bool) {
	d := ResourcesData{UpdatedAt: reportReceivedAt(agentID)}
	hasData := false

	if raw := loadCollectorRaw(agentID, "cpu"); raw != nil {
		var cpu rentalCPUCollectorResult
		if err := json.Unmarshal(raw, &cpu); err == nil {
			d.CPUPct = cpu.UsagePercent
			hasData = true
		}
	}
	if raw := loadCollectorRaw(agentID, "loadavg"); raw != nil {
		var load rentalLoadavgCollectorResult
		if err := json.Unmarshal(raw, &load); err == nil {
			d.Load1 = load.Load1
			d.Load5 = load.Load5
			d.Load15 = load.Load15
			hasData = true
		}
	}
	if raw := loadCollectorRaw(agentID, "memory"); raw != nil {
		var mem rentalMemoryCollectorResult
		if err := json.Unmarshal(raw, &mem); err == nil {
			d.MemTotal = mem.PhysMemBytes
			d.RAMTotal = humanGiB(mem.PhysMemBytes)
			hasData = true
		}
	}
	if raw := loadCollectorRaw(agentID, "network"); raw != nil {
		var netData rentalNetworkCollectorResult
		if err := json.Unmarshal(raw, &netData); err == nil {
			d.NetRxBytes = netData.RxBytes
			d.NetTxBytes = netData.TxBytes
			d.NetRxHuman = humanBytesReport(netData.RxBytes)
			d.NetTxHuman = humanBytesReport(netData.TxBytes)
			hasData = true
		}
	}
	if raw := loadCollectorRaw(agentID, "host"); raw != nil {
		var host rentalHostCollectorResult
		if err := json.Unmarshal(raw, &host); err == nil {
			d.OSLabel = strings.TrimSpace(host.OS)
			hasData = true
		}
	}
	if raw := loadCollectorRaw(agentID, "disk"); raw != nil {
		var disks []rentalDiskOverviewEntry
		if err := json.Unmarshal(raw, &disks); err == nil {
			for _, disk := range disks {
				if disk.Mounted != "/" {
					continue
				}
				d.DiskTotal = disk.Size
				d.DiskUsed = disk.Used
				d.DiskFree = disk.Avail
				d.DiskPct = disk.UsePercent
				hasData = true
				break
			}
		}
	}

	return d, hasData
}

func processesFromReport(agentID string) (ProcessesResponse, bool) {
	raw := loadCollectorRaw(agentID, "process")
	if raw == nil {
		return ProcessesResponse{}, false
	}
	var rows []rentalProcessCollectorEntry
	if err := json.Unmarshal(raw, &rows); err != nil {
		return ProcessesResponse{}, false
	}

	type processSortable struct {
		info ProcessInfo
		cpu  float64
		mem  float64
	}
	parsed := make([]processSortable, 0, len(rows))
	for _, row := range rows {
		rssKB, _ := strconv.ParseInt(strings.TrimSpace(row.RSS), 10, 64)
		parsed = append(parsed, processSortable{
			info: ProcessInfo{
				PID:     strings.TrimSpace(row.PID),
				CPU:     strings.TrimSpace(row.CPU),
				Mem:     strings.TrimSpace(row.Mem),
				RSS:     rssKB * 1024,
				Command: shortProcessCommand(row.Command),
			},
			cpu: parsePercentFloat(row.CPU),
			mem: parsePercentFloat(row.Mem),
		})
	}

	topCPU := make([]processSortable, len(parsed))
	copy(topCPU, parsed)
	sort.SliceStable(topCPU, func(i, j int) bool {
		if topCPU[i].cpu == topCPU[j].cpu {
			return topCPU[i].info.PID < topCPU[j].info.PID
		}
		return topCPU[i].cpu > topCPU[j].cpu
	})

	topMem := make([]processSortable, len(parsed))
	copy(topMem, parsed)
	sort.SliceStable(topMem, func(i, j int) bool {
		if topMem[i].mem == topMem[j].mem {
			return topMem[i].info.PID < topMem[j].info.PID
		}
		return topMem[i].mem > topMem[j].mem
	})

	resp := ProcessesResponse{
		TopCPU: make([]ProcessInfo, 0, len(topCPU)),
		TopMem: make([]ProcessInfo, 0, len(topMem)),
		Total:  len(parsed),
	}
	for _, row := range topCPU {
		resp.TopCPU = append(resp.TopCPU, row.info)
	}
	for _, row := range topMem {
		resp.TopMem = append(resp.TopMem, row.info)
	}
	return resp, true
}

func backupAPIDataFromReport(agentID string) (BackupAPIData, bool) {
	raw := loadCollectorRaw(agentID, "backup")
	if raw == nil {
		return BackupAPIData{}, false
	}
	var backup backupCollectorResult
	if err := json.Unmarshal(raw, &backup); err != nil {
		return BackupAPIData{}, false
	}
	if backup.DBSize == "" {
		backup.DBSize = "?"
	}
	return BackupAPIData{
		BackupFiles:   backup.BackupFiles,
		NCBackupFiles: backup.NCBackupFiles,
		DBSize:        backup.DBSize,
		DBList:        backup.DBList,
	}, true
}

func r2MetricsFromReport(agentID string) (R2MetricsData, bool) {
	raw := loadCollectorRaw(agentID, "cloudflare")
	if raw == nil {
		return R2MetricsData{}, false
	}
	var payload cloudflareCollectorResult
	if err := json.Unmarshal(raw, &payload); err != nil {
		return R2MetricsData{}, false
	}

	result := R2MetricsData{}
	if payload.Storage != nil {
		storage := &R2StorageInfo{
			PayloadSize: payload.Storage.PayloadSize,
			ObjectCount: payload.Storage.ObjectCount,
			Buckets:     map[string]R2BucketInfo{},
		}
		for name, bucket := range payload.Storage.Buckets {
			storage.Buckets[name] = R2BucketInfo{
				PayloadSize: bucket.PayloadSize,
				ObjectCount: bucket.ObjectCount,
			}
		}
		result.Storage = storage
	}
	if payload.Operations != nil {
		result.Operations = &R2OperationsInfo{
			ClassA: payload.Operations.ClassA,
			ClassB: payload.Operations.ClassB,
			Month:  payload.Operations.Month,
		}
	}
	return result, true
}

func parsePercentFloat(raw string) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(raw, "%")), 64)
	if err != nil {
		return 0
	}
	return v
}

func shortProcessCommand(raw string) string {
	cmd := strings.TrimSpace(raw)
	if cmd == "" {
		return ""
	}
	fields := strings.Fields(cmd)
	if len(fields) > 0 {
		cmd = fields[0]
	}
	if idx := strings.LastIndex(cmd, "/"); idx >= 0 && idx+1 < len(cmd) {
		cmd = cmd[idx+1:]
	}
	return cmd
}

func systemHostOSLabel(sys systemCollectorResult) string {
	if sys.Host.OSPrettyName != "" {
		return sys.Host.OSPrettyName
	}
	return strings.TrimSpace(sys.Host.OSName + " " + sys.Host.OSVersion)
}

// humanBytesReport は int64 バイト数を "3.5G" 形式の文字列に変換する（df -h 互換）
func humanBytesReport(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(b)/float64(div), "KMGTPE"[exp])
}
