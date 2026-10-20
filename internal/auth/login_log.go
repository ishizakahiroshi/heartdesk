package auth

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// LoginLogPath は既定のログイン監査ログパス。
// 環境変数 SAB_LOGIN_LOG_PATH で上書きできる（LoginLogResolvedPath を参照）。
const LoginLogPath = "/home/sab/log/sab_login_events.jsonl" // secrets-scan: allow

// LoginLogResolvedPath は実際に読み書きするログインログのパスを返す。
// SAB_LOGIN_LOG_PATH が設定されていればそれを、無ければ LoginLogPath を使う。
func LoginLogResolvedPath() string {
	if p := strings.TrimSpace(os.Getenv("SAB_LOGIN_LOG_PATH")); p != "" {
		return p
	}
	return LoginLogPath
}

// LoginLogEntry は1件のログインイベント記録
type LoginLogEntry struct {
	Time    string `json:"time"`   // RFC3339
	Result  string `json:"result"` // "success" / "fail"
	User    string `json:"user"`   // ユーザー名（失敗時は入力値）
	IP      string `json:"ip"`
	UA      string `json:"ua"`
	PwStats string `json:"pw_stats,omitempty"` // 失敗時のみ: パスワード統計
	Reason  string `json:"reason,omitempty"`   // "totp_fail" / "lockout" / "bad_credential"
}

var loginLogMu sync.Mutex

func AppendLoginLog(e LoginLogEntry) {
	if e.Time == "" {
		e.Time = time.Now().Format(time.RFC3339)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')

	loginLogMu.Lock()
	defer loginLogMu.Unlock()
	path := LoginLogResolvedPath()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		log.Printf("auth: login log open %s failed: %v", path, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		log.Printf("auth: login log write %s failed: %v", path, err)
	}
}
