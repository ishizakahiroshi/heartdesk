package store

import (
	"context"
	"database/sql"
	"fmt"
)

type sqliteAgentStore struct{ db *sql.DB }

// NewAgentStore は AgentStore の SQLite 実装を返す。
func NewAgentStore(db *sql.DB) AgentStore {
	return &sqliteAgentStore{db: db}
}

func (s *sqliteAgentStore) UpsertAgent(ctx context.Context, tenantID string, a Agent) error {
	const q = `INSERT INTO agents (tenant_id, agent_id, agent_label, agent_type, last_received_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, agent_id) DO UPDATE SET
			agent_label      = excluded.agent_label,
			agent_type       = excluded.agent_type,
			last_received_at = excluded.last_received_at`
	var lastRecv *string
	if a.LastReceivedAt != nil {
		s := a.LastReceivedAt.UTC().Format(storeTimeLayout)
		lastRecv = &s
	}
	if _, err := s.db.ExecContext(ctx, q, tenantID, a.AgentID, a.AgentLabel, a.AgentType, lastRecv, nowStoreTime()); err != nil {
		return fmt.Errorf("store.UpsertAgent: %w", err)
	}
	return nil
}

func (s *sqliteAgentStore) GetAgents(ctx context.Context, tenantID string) ([]Agent, error) {
	const q = `SELECT id, tenant_id, agent_id, agent_label, agent_type, last_received_at, created_at
		FROM agents WHERE tenant_id = ? ORDER BY agent_id`
	rows, err := s.db.QueryContext(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store.GetAgents: %w", err)
	}
	defer rows.Close()
	return scanAgents(rows)
}

func (s *sqliteAgentStore) GetAgentByID(ctx context.Context, tenantID, agentID string) (*Agent, error) {
	const q = `SELECT id, tenant_id, agent_id, agent_label, agent_type, last_received_at, created_at
		FROM agents WHERE tenant_id = ? AND agent_id = ?`
	row := s.db.QueryRowContext(ctx, q, tenantID, agentID)
	return scanAgent(row)
}

func (s *sqliteAgentStore) GetAgentsAcrossTenants(ctx context.Context) ([]Agent, error) {
	const q = `SELECT id, tenant_id, agent_id, agent_label, agent_type, last_received_at, created_at
		FROM agents ORDER BY tenant_id, agent_id`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("store.GetAgentsAcrossTenants: %w", err)
	}
	defer rows.Close()
	return scanAgents(rows)
}

// --- scan helpers ---

func scanAgent(row *sql.Row) (*Agent, error) {
	var a Agent
	var lastRecv, createdAt sql.NullString
	err := row.Scan(&a.ID, &a.TenantID, &a.AgentID, &a.AgentLabel, &a.AgentType, &lastRecv, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store.scanAgent: %w", err)
	}
	if lastRecv.Valid {
		t := parseStoreTime(lastRecv.String)
		a.LastReceivedAt = &t
	}
	if createdAt.Valid {
		a.CreatedAt = parseStoreTime(createdAt.String)
	}
	return &a, nil
}

func scanAgents(rows *sql.Rows) ([]Agent, error) {
	var out []Agent
	for rows.Next() {
		var a Agent
		var lastRecv, createdAt sql.NullString
		if err := rows.Scan(&a.ID, &a.TenantID, &a.AgentID, &a.AgentLabel, &a.AgentType, &lastRecv, &createdAt); err != nil {
			return nil, fmt.Errorf("store.scanAgents: %w", err)
		}
		if lastRecv.Valid {
			t := parseStoreTime(lastRecv.String)
			a.LastReceivedAt = &t
		}
		if createdAt.Valid {
			a.CreatedAt = parseStoreTime(createdAt.String)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.scanAgents rows: %w", err)
	}
	return out, nil
}
