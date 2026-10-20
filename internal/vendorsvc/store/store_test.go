package store_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"
)

// openTestDB はテスト用の一時 DB を作成するヘルパ。
func openTestDB(t *testing.T) *store.Stores {
	t.Helper()
	s, _ := openTestDBWithRaw(t)
	return s
}

// openTestDBWithRaw は openTestDB と同じ初期化を行い、追加で生の *sql.DB も返す。
// MigrateLedgerFromJSONFile のように *sql.DB を直接受け取る関数のテストで使う。
func openTestDBWithRaw(t *testing.T) (*store.Stores, *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := vendorsvc.OpenDB(filepath.Join(dir, "vendor.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &store.Stores{
		Tenant:  store.NewTenantStore(db),
		User:    store.NewUserStore(db),
		Agent:   store.NewAgentStore(db),
		Report:  store.NewReportStore(db),
		Audit:   store.NewAuditStore(db),
		Ledger:  store.NewLedgerStore(db),
		Session: store.NewSessionStore(db),
	}, db
}

// TestTenantCRUD は CreateTenant → GetTenant の往復を検証する。
func TestTenantCRUD(t *testing.T) {
	ctx := context.Background()
	s := openTestDB(t)

	tenant := store.Tenant{
		ID:                 "tenant-b",
		Name:               "Tenant A",
		Type:               "monitor_owned",
		VendorRelayEnabled: false,
	}

	if err := s.Tenant.CreateTenant(ctx, tenant); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	got, err := s.Tenant.GetTenant(ctx, "tenant-b")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got == nil {
		t.Fatal("GetTenant returned nil")
	}
	if got.ID != tenant.ID {
		t.Errorf("ID = %q, want %q", got.ID, tenant.ID)
	}
	if got.Name != tenant.Name {
		t.Errorf("Name = %q, want %q", got.Name, tenant.Name)
	}
	if got.Type != tenant.Type {
		t.Errorf("Type = %q, want %q", got.Type, tenant.Type)
	}

	// C-002 regression: CreateTenant 後の created_at / updated_at が
	// parseStoreTime のフォーマット不一致でゼロ値にならないこと（datetime('now') と
	// "2006-01-02T15:04:05Z" の整合性）。
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero (C-002 regression: parseStoreTime layout mismatch)")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt is zero (C-002 regression: parseStoreTime layout mismatch)")
	}
}

// TestParseStoreTimeFallback は parseStoreTime が SQLite の datetime('now') 既定形式
// （"YYYY-MM-DD HH:MM:SS"）と Go 側 ISO8601 形式（"2006-01-02T15:04:05Z"）の両方を
// パースできることを確認する（C-002 回帰防止）。
func TestParseStoreTimeFallback(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"sqlite datetime('now') format", "2026-06-15 16:36:05"},
		{"go store layout (ISO8601 Z)", "2026-06-15T16:36:05Z"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := store.ParseStoreTimeForTest(c.in)
			if got.IsZero() {
				t.Errorf("parseStoreTime(%q) returned zero (layout fallback failed)", c.in)
			}
			if got.Year() != 2026 || got.Month() != 6 || got.Day() != 15 {
				t.Errorf("parseStoreTime(%q) = %v, want 2026-06-15", c.in, got)
			}
		})
	}
}

// TestSessionCreateTimestamps は CreateSession 後の created_at / last_seen_at が
// ゼロ値にならないことを確認する（C-002 回帰防止: Session 用テストはこれが既存にない）。
func TestSessionCreateTimestamps(t *testing.T) {
	ctx := context.Background()
	s := openTestDB(t)

	if err := s.Tenant.CreateTenant(ctx, store.Tenant{ID: "tenant-b", Name: "tenant-b", Type: "monitor_owned"}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if err := s.User.CreateUser(ctx, "tenant-b", store.User{Email: "test@example.com", PasswordHash: "x"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u, err := s.User.GetUserByEmail(ctx, "tenant-b", "test@example.com")
	if err != nil || u == nil {
		t.Fatalf("GetUserByEmail: %v u=%v", err, u)
	}
	if u.CreatedAt.IsZero() {
		t.Error("User.CreatedAt is zero (C-002 regression)")
	}

	sess := store.Session{
		ID:        "sess-1",
		UserID:    u.ID,
		CSRFToken: "csrf",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := s.Session.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := s.Session.GetSession(ctx, "sess-1")
	if err != nil || got == nil {
		t.Fatalf("GetSession: %v got=%v", err, got)
	}
	if got.CreatedAt.IsZero() {
		t.Error("Session.CreatedAt is zero (C-002 regression)")
	}
	if got.LastSeenAt.IsZero() {
		t.Error("Session.LastSeenAt is zero (C-002 regression)")
	}
}

// TestLedgerIssuedAtNotZero は AppendLedger 後の issued_at が非ゼロであることを
// 確認する（C-002 回帰防止）。
func TestLedgerIssuedAtNotZero(t *testing.T) {
	ctx := context.Background()
	s := openTestDB(t)

	actor := "tester"
	prefix := "tenant-b.tenant-b-vps-foo."
	if err := s.Ledger.AppendLedger(ctx, "tenant-b", store.LedgerEntry{
		Action:    "issue",
		TenantID:  "tenant-b",
		AgentID:   "tenant-b-vps-foo",
		Actor:     &actor,
		KeyPrefix: &prefix,
	}); err != nil {
		t.Fatalf("AppendLedger: %v", err)
	}
	entries, err := s.Ledger.ListLedger(ctx, "tenant-b")
	if err != nil {
		t.Fatalf("ListLedger: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].IssuedAt.IsZero() {
		t.Error("Ledger.IssuedAt is zero (C-002 regression: datetime('now') / parseStoreTime mismatch)")
	}
}

// TestAgentUpsert は UpsertAgent 2回で行が1つ（UNIQUE効き）、last_received_at が更新されることを確認。
func TestAgentUpsert(t *testing.T) {
	ctx := context.Background()
	s := openTestDB(t)

	// テナントを先に作成（FK 制約）
	if err := s.Tenant.CreateTenant(ctx, store.Tenant{ID: "tenant-b", Name: "Tenant1", Type: "monitor_owned"}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	t1 := time.Now().UTC().Truncate(time.Second)
	agent := store.Agent{
		TenantID:       "tenant-b",
		AgentID:        "tenant-b-vps-sakura",
		AgentLabel:     "ih.example.jp",
		AgentType:      "vps",
		LastReceivedAt: &t1,
	}
	if err := s.Agent.UpsertAgent(ctx, "tenant-b", agent); err != nil {
		t.Fatalf("UpsertAgent (1st): %v", err)
	}

	// 2回目：last_received_at を更新
	t2 := t1.Add(time.Minute)
	agent.LastReceivedAt = &t2
	if err := s.Agent.UpsertAgent(ctx, "tenant-b", agent); err != nil {
		t.Fatalf("UpsertAgent (2nd): %v", err)
	}

	// 行が1件のみ存在すること
	agents, err := s.Agent.GetAgents(ctx, "tenant-b")
	if err != nil {
		t.Fatalf("GetAgents: %v", err)
	}
	if len(agents) != 1 {
		t.Errorf("len(agents) = %d, want 1", len(agents))
	}

	// last_received_at が更新されていること
	got, err := s.Agent.GetAgentByID(ctx, "tenant-b", "tenant-b-vps-sakura")
	if err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}
	if got == nil {
		t.Fatal("GetAgentByID returned nil")
	}
	if got.LastReceivedAt == nil || !got.LastReceivedAt.Equal(t2) {
		var gotTime time.Time
		if got.LastReceivedAt != nil {
			gotTime = *got.LastReceivedAt
		}
		t.Errorf("LastReceivedAt = %v, want %v", gotTime, t2)
	}
}

// TestRawReportTenantIsolation は InsertRawReport 後、tenantID="tenant-b" では取得でき、"tenant-c" では0件であることを確認。
func TestRawReportTenantIsolation(t *testing.T) {
	ctx := context.Background()
	s := openTestDB(t)

	// テナント作成（FK 制約）
	for _, id := range []string{"tenant-b", "tenant-c"} {
		if err := s.Tenant.CreateTenant(ctx, store.Tenant{ID: id, Name: id, Type: "monitor_owned"}); err != nil {
			t.Fatalf("CreateTenant %s: %v", id, err)
		}
	}

	now := time.Now().UTC()
	r := store.RawReport{
		TenantID:       "tenant-b",
		AgentID:        "tenant-b-vps-sakura",
		ReceivedAt:     now,
		ReportedAt:     now,
		CollectorsJSON: `{"test":true}`,
	}
	if err := s.Report.InsertRawReport(ctx, "tenant-b", r); err != nil {
		t.Fatalf("InsertRawReport: %v", err)
	}

	// tenant-b では取得できること
	reports, err := s.Report.ListRawReports(ctx, "tenant-b", "tenant-b-vps-sakura",
		now.Add(-time.Hour), now.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("ListRawReports tenant-b: %v", err)
	}
	if len(reports) != 1 {
		t.Errorf("tenant-b reports = %d, want 1", len(reports))
	}

	// tenant-c では0件であること（テナント隔離確認）
	reports2, err := s.Report.ListRawReports(ctx, "tenant-c", "tenant-b-vps-sakura",
		now.Add(-time.Hour), now.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("ListRawReports tenant-c: %v", err)
	}
	if len(reports2) != 0 {
		t.Errorf("tenant-c reports = %d, want 0 (isolation failure)", len(reports2))
	}
}

// TestAuditIsolation は AppendAudit(tenant-b) 10件後に ListAuditAcrossTenants=10件、ListAudit("tenant-c",...)=0件を確認。
func TestAuditIsolation(t *testing.T) {
	ctx := context.Background()
	s := openTestDB(t)

	for _, id := range []string{"tenant-b", "tenant-c"} {
		if err := s.Tenant.CreateTenant(ctx, store.Tenant{ID: id, Name: id, Type: "monitor_owned"}); err != nil {
			t.Fatalf("CreateTenant %s: %v", id, err)
		}
	}

	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC().Add(time.Hour)

	for i := 0; i < 10; i++ {
		if err := s.Audit.AppendAudit(ctx, "tenant-b", store.AuditEntry{
			EventType: "test_event",
		}); err != nil {
			t.Fatalf("AppendAudit[%d]: %v", i, err)
		}
	}

	// 横断クエリ: 10件
	all, err := s.Audit.ListAuditAcrossTenants(ctx, from, to, 100)
	if err != nil {
		t.Fatalf("ListAuditAcrossTenants: %v", err)
	}
	if len(all) != 10 {
		t.Errorf("AcrossTenants count = %d, want 10", len(all))
	}

	// tenant-c では0件（隔離確認）
	tenantCAudit, err := s.Audit.ListAudit(ctx, "tenant-c", from, to, 100)
	if err != nil {
		t.Fatalf("ListAudit tenant-c: %v", err)
	}
	if len(tenantCAudit) != 0 {
		t.Errorf("tenant-c audit count = %d, want 0 (isolation failure)", len(tenantCAudit))
	}
}

// TestAppendLedger_AutoCreatesTenant は、tenants 行がまだ無いテナントへの
// ライセンス発行（AppendLedger）が FK 制約違反にならず、親 tenants 行を自動作成して
// 台帳行を記録することを検証する（新規プロビジョニング直後の発行を壊さないための回帰テスト）。
func TestAppendLedger_AutoCreatesTenant(t *testing.T) {
	ctx := context.Background()
	s := openTestDB(t)

	// tenants に "t005" は存在しない状態で発行する。
	if got, _ := s.Tenant.GetTenant(ctx, "t005"); got != nil {
		t.Fatalf("precondition: tenant t005 should not exist")
	}

	actor := "vendor_staff_user"
	prefix := "t005.t005-vps-foo."
	if err := s.Ledger.AppendLedger(ctx, "t005", store.LedgerEntry{
		Action:    "issue",
		TenantID:  "t005",
		AgentID:   "t005-vps-foo",
		Actor:     &actor,
		KeyPrefix: &prefix,
	}); err != nil {
		t.Fatalf("AppendLedger to unregistered tenant failed (FK regression): %v", err)
	}

	// 親 tenants 行が自動作成されていること。
	tn, err := s.Tenant.GetTenant(ctx, "t005")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if tn == nil {
		t.Fatal("tenant t005 was not auto-created by AppendLedger")
	}
	if tn.Type != "monitor_owned" {
		t.Errorf("auto-created tenant type = %q, want monitor_owned", tn.Type)
	}

	// 台帳行が記録されていること。
	entries, err := s.Ledger.ListLedger(ctx, "t005")
	if err != nil {
		t.Fatalf("ListLedger: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1", len(entries))
	}
	if entries[0].Action != "issue" || entries[0].AgentID != "t005-vps-foo" {
		t.Errorf("ledger entry = %+v, unexpected", entries[0])
	}
}

// TestMigrateLedgerFromJSONFile_AutoCreatesTenants は、tenants テーブルがまだ空の状態で
// 旧 JSON 台帳に未登録テナント (tenant-a, tenant-b) のエントリが含まれていても、
// MigrateLedgerFromJSONFile が FK 制約違反で失敗せず、親 tenants 行を担保した上で
// 全行を license_ledger に取り込めることを検証する（C-014 回帰テスト）。
func TestMigrateLedgerFromJSONFile_AutoCreatesTenants(t *testing.T) {
	ctx := context.Background()
	s, db := openTestDBWithRaw(t)

	// 前提: tenants は空
	if got, _ := s.Tenant.GetTenant(ctx, "tenant-a"); got != nil {
		t.Fatalf("precondition: tenant tenant-a should not exist")
	}
	if got, _ := s.Tenant.GetTenant(ctx, "tenant-b"); got != nil {
		t.Fatalf("precondition: tenant tenant-b should not exist")
	}

	// 旧 JSON 台帳を作成（複数テナント・新しい順）
	legacy := []map[string]interface{}{
		{
			"timestamp":  "2026-03-02T10:00:00Z",
			"action":     "revoke",
			"tenant_id":  "tenant-b",
			"agent_id":   "tenant-b-vps-sakura",
			"kid":        "kid-2",
			"key_prefix": "tenant-b.tenant-b-vps-sakura.aaa",
			"actor":      "vendor_staff",
			"reason":     "rotated",
		},
		{
			"timestamp":  "2026-03-01T09:00:00Z",
			"action":     "issue",
			"tenant_id":  "tenant-b",
			"agent_id":   "tenant-b-vps-sakura",
			"kid":        "kid-1",
			"key_prefix": "tenant-b.tenant-b-vps-sakura.aaa",
			"actor":      "vendor_staff",
		},
		{
			"timestamp":  "2026-02-15T12:00:00Z",
			"action":     "issue",
			"tenant_id":  "tenant-a",
			"agent_id":   "tenant-a-vps-host-1",
			"kid":        "kid-0",
			"key_prefix": "tenant-a.tenant-a-vps-host-1.bbb",
			"actor":      "vendor_staff",
		},
	}
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "vendor_license_ledger.json")
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(jsonPath, raw, 0o600); err != nil {
		t.Fatalf("write json: %v", err)
	}

	// 取り込み: FK 違反で失敗せず、3 件すべて入ること（C-014 回帰）
	n, err := store.MigrateLedgerFromJSONFile(ctx, db, jsonPath)
	if err != nil {
		t.Fatalf("MigrateLedgerFromJSONFile failed (FK regression): %v", err)
	}
	if n != 3 {
		t.Fatalf("migrated count = %d, want 3", n)
	}

	// 親 tenants 行が自動作成されていること
	for _, id := range []string{"tenant-a", "tenant-b"} {
		tn, err := s.Tenant.GetTenant(ctx, id)
		if err != nil {
			t.Fatalf("GetTenant %s: %v", id, err)
		}
		if tn == nil {
			t.Fatalf("tenant %s was not auto-created by MigrateLedgerFromJSONFile", id)
		}
		if tn.Type != "monitor_owned" {
			t.Errorf("auto-created tenant %s type = %q, want monitor_owned", id, tn.Type)
		}
	}

	// 台帳行が両テナントに記録されていること
	t000Entries, err := s.Ledger.ListLedger(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("ListLedger tenant-a: %v", err)
	}
	if len(t000Entries) != 1 {
		t.Errorf("tenant-a ledger entries = %d, want 1", len(t000Entries))
	}
	t001Entries, err := s.Ledger.ListLedger(ctx, "tenant-b")
	if err != nil {
		t.Fatalf("ListLedger tenant-b: %v", err)
	}
	if len(t001Entries) != 2 {
		t.Errorf("tenant-b ledger entries = %d, want 2", len(t001Entries))
	}

	// 既に license_ledger に行がある状態での再呼び出しは no-op（冪等）
	n2, err := store.MigrateLedgerFromJSONFile(ctx, db, jsonPath)
	if err != nil {
		t.Fatalf("MigrateLedgerFromJSONFile (re-run) failed: %v", err)
	}
	if n2 != 0 {
		t.Errorf("re-run migrated count = %d, want 0 (idempotent)", n2)
	}
}

// TestUpdateUserPasswordTenantBoundary は C-036 回帰防止:
//   - tenantID="" の UpdateUserPassword はエラーになる（テナント境界を保証）
//   - 別テナント所属ユーザーへの UpdateUserPassword は no-op（ハッシュは変わらない）
//   - 同テナント所属ユーザーへの UpdateUserPassword は成功する
//   - CLI 用 UpdateUserPasswordAcrossTenants は user_tenants 照合なしで更新できる
func TestUpdateUserPasswordTenantBoundary(t *testing.T) {
	ctx := context.Background()
	s := openTestDB(t)

	// 2 テナント作成
	for _, id := range []string{"tenant-b", "tenant-c"} {
		if err := s.Tenant.CreateTenant(ctx, store.Tenant{ID: id, Name: id, Type: "monitor_owned"}); err != nil {
			t.Fatalf("CreateTenant %s: %v", id, err)
		}
	}

	// tenant-b に user-a, tenant-c に user-b を作成
	if err := s.User.CreateUser(ctx, "tenant-b", store.User{Email: "a@example.com", PasswordHash: "hash-a-orig"}); err != nil {
		t.Fatalf("CreateUser a: %v", err)
	}
	if err := s.User.CreateUser(ctx, "tenant-c", store.User{Email: "b@example.com", PasswordHash: "hash-b-orig"}); err != nil {
		t.Fatalf("CreateUser b: %v", err)
	}

	userA, err := s.User.GetUserByEmail(ctx, "tenant-b", "a@example.com")
	if err != nil || userA == nil {
		t.Fatalf("GetUserByEmail a: %v u=%v", err, userA)
	}
	userB, err := s.User.GetUserByEmail(ctx, "tenant-c", "b@example.com")
	if err != nil || userB == nil {
		t.Fatalf("GetUserByEmail b: %v u=%v", err, userB)
	}

	// (1) tenantID="" 経路はエラーになる（store 層で防止）
	if err := s.User.UpdateUserPassword(ctx, "", userA.ID, "hash-injected"); err == nil {
		t.Error("UpdateUserPassword(tenantID=\"\") should return error (C-036 regression)")
	}

	// (1') user-b のハッシュが書き換わっていないことを確認（横断攻撃が成立しないこと）
	gotB, err := s.User.GetUserByEmailAcrossTenants(ctx, "b@example.com")
	if err != nil || gotB == nil {
		t.Fatalf("GetUserByEmailAcrossTenants b: %v u=%v", err, gotB)
	}
	if gotB.PasswordHash != "hash-b-orig" {
		t.Errorf("user-b password leaked across tenant boundary: got %q, want %q (C-036)", gotB.PasswordHash, "hash-b-orig")
	}

	// (2) 別テナント (tenant-b) からの UpdateUserPassword(userB) は user_tenants 照合で no-op
	if err := s.User.UpdateUserPassword(ctx, "tenant-b", userB.ID, "hash-b-cross"); err != nil {
		t.Fatalf("UpdateUserPassword cross-tenant (should silently no-op): %v", err)
	}
	gotB2, err := s.User.GetUserByEmailAcrossTenants(ctx, "b@example.com")
	if err != nil || gotB2 == nil {
		t.Fatalf("GetUserByEmailAcrossTenants b (2): %v u=%v", err, gotB2)
	}
	if gotB2.PasswordHash != "hash-b-orig" {
		t.Errorf("user-b password changed by cross-tenant call: got %q, want %q", gotB2.PasswordHash, "hash-b-orig")
	}

	// (3) 同テナントからの UpdateUserPassword は成功
	if err := s.User.UpdateUserPassword(ctx, "tenant-b", userA.ID, "hash-a-new"); err != nil {
		t.Fatalf("UpdateUserPassword same-tenant: %v", err)
	}
	gotA, err := s.User.GetUserByEmail(ctx, "tenant-b", "a@example.com")
	if err != nil || gotA == nil {
		t.Fatalf("GetUserByEmail a (after update): %v u=%v", err, gotA)
	}
	if gotA.PasswordHash != "hash-a-new" {
		t.Errorf("user-a password not updated: got %q, want %q", gotA.PasswordHash, "hash-a-new")
	}

	// (4) CLI 用 UpdateUserPasswordAcrossTenants は user_tenants 照合なしで更新できる
	if err := s.User.UpdateUserPasswordAcrossTenants(ctx, userB.ID, "hash-b-cli"); err != nil {
		t.Fatalf("UpdateUserPasswordAcrossTenants: %v", err)
	}
	gotB3, err := s.User.GetUserByEmailAcrossTenants(ctx, "b@example.com")
	if err != nil || gotB3 == nil {
		t.Fatalf("GetUserByEmailAcrossTenants b (3): %v u=%v", err, gotB3)
	}
	if gotB3.PasswordHash != "hash-b-cli" {
		t.Errorf("CLI cross-tenant update failed: got %q, want %q", gotB3.PasswordHash, "hash-b-cli")
	}
}
