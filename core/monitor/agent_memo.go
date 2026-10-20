package monitor

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
)

// AgentMemoStore は agent_memo.json の読み書きを管理する。
type AgentMemoStore struct {
	mu   sync.RWMutex
	data map[string]string
	path string
}

var globalMemoStore *AgentMemoStore

// NewAgentMemoStore は dataDir/agent_memo.json を読み込んでストアを初期化する。
// ファイルが存在しない場合は空 map で初期化する。
func NewAgentMemoStore(dataDir string) *AgentMemoStore {
	path := filepath.Join(dataDir, "agent_memo.json")
	s := &AgentMemoStore{
		data: map[string]string{},
		path: path,
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("ERROR: agent_memo: load error: %v", err)
		}
		return s
	}
	if len(data) == 0 {
		return s
	}
	if err := json.Unmarshal(data, &s.data); err != nil {
		log.Printf("ERROR: agent_memo: parse error: %v", err)
		s.data = map[string]string{}
	}
	return s
}

// InitAgentMemoStore はグローバルストアを初期化する。起動時に呼び出す。
func InitAgentMemoStore() {
	dataDir := sab.SabPath("data/json")
	globalMemoStore = NewAgentMemoStore(dataDir)
}

// GetAll は全件のメモを返す（コピー）。
func (s *AgentMemoStore) GetAll() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.data))
	for k, v := range s.data {
		out[k] = v
	}
	return out
}

// Set はメモを更新し、JSONファイルにアトミック書き込みする。
func (s *AgentMemoStore) Set(agentID, memo string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if memo == "" {
		delete(s.data, agentID)
	} else {
		s.data[agentID] = memo
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return fmt.Errorf("agent_memo: mkdir error: %w", err)
	}

	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("agent_memo: marshal error: %w", err)
	}
	raw = append(raw, '\n')

	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0600); err != nil {
		return fmt.Errorf("agent_memo: write tmp error: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("agent_memo: rename error: %w", err)
	}
	return nil
}

// GetAgentMemoAll はグローバルストアから全件を返す。
func GetAgentMemoAll() map[string]string {
	if globalMemoStore == nil {
		return map[string]string{}
	}
	return globalMemoStore.GetAll()
}

// APIAgentMemo は POST /api/monitor/agent-memo のパブリックハンドラー。
func (h *Handler) APIAgentMemo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	h.actionAgentMemo(w, r)
}

// --- POST ハンドラー（内部）---

type agentMemoRequest struct {
	AgentID string `json:"agent_id"`
	Memo    string `json:"memo"`
}

// actionAgentMemo は POST ?api=agent_memo_save に対応するハンドラー。
func (h *Handler) actionAgentMemo(w http.ResponseWriter, r *http.Request) {
	// ログイン済みチェック
	if _, ok := auth.DefaultSessionManager().SessionFromRequest(r); !ok {
		writeActionError(w, "ログインが必要です", http.StatusUnauthorized)
		return
	}

	var req agentMemoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeActionError(w, "リクエスト形式が不正です", http.StatusBadRequest)
		return
	}
	agentID := strings.TrimSpace(req.AgentID)
	if agentID == "" {
		writeActionError(w, "agent_id は必須です", http.StatusBadRequest)
		return
	}
	// body の agent_id も形式・テナント境界を検証する。
	if !isValidAgentID(agentID) {
		writeActionError(w, "agent_id 形式が不正です", http.StatusBadRequest)
		return
	}
	if !enforceAgentTenantBoundary(r, agentID) {
		writeActionError(w, "このテナントではこの agent を操作できません", http.StatusForbidden)
		return
	}

	if globalMemoStore == nil {
		writeActionError(w, "メモストアが未初期化です", http.StatusInternalServerError)
		return
	}

	if err := globalMemoStore.Set(agentID, req.Memo); err != nil {
		log.Printf("ERROR: agent_memo: set error: %v", err)
		writeActionError(w, "保存に失敗しました: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
