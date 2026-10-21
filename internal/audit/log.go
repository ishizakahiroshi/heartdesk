package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

// 監査ログの保存形式:
//   - 旧: 単一ファイル data/json/audit_log.jsonl
//   - 新: 日付別ファイル <logDir>/audit_log.jsonl.YYYY-MM-DD
//   - Agent 側 audit_log_tail collector は同ディレクトリを glob して tail する
//
// 環境変数:
//   - HEARTDESK_AUDIT_LOG_DIR: 書き込み先ディレクトリ（既定: data/audit）
//   - HEARTDESK_AUDIT_LOG_PATH: 旧仕様。設定されていれば後方互換でそのファイルに書く（既存テスト用）。
const (
	defaultLogDir    = "data/audit"
	legacyLogPath    = "data/json/audit_log.jsonl"
	logFilePrefix    = "audit_log.jsonl."
	defaultListLimit = 200
	maxListLimit     = 5000
)

type Event struct {
	Time     string            `json:"time"`
	Event    string            `json:"event"`
	User     string            `json:"user"`
	Role     string            `json:"role,omitempty"`
	IP       string            `json:"ip,omitempty"`
	Method   string            `json:"method,omitempty"`
	Path     string            `json:"path,omitempty"`
	Query    string            `json:"query,omitempty"`
	Result   string            `json:"result"`
	Message  string            `json:"message,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type Filter struct {
	User   string
	Event  string
	Result string
	Query  string
	From   *time.Time
	To     *time.Time
	Limit  int
}

var (
	writeMu       sync.Mutex
	migrationOnce sync.Once
)

func LogRequest(r *http.Request, event, user, role, result, message string, metadata map[string]string) {
	rec := Event{
		Event:   strings.TrimSpace(event),
		User:    strings.TrimSpace(user),
		Role:    strings.TrimSpace(role),
		IP:      "",
		Method:  "",
		Path:    "",
		Query:   "",
		Result:  normalizeResult(result),
		Message: strings.TrimSpace(message),
	}
	if rec.User == "" {
		rec.User = "-"
	}
	if r != nil {
		rec.IP = strings.TrimSpace(r.Header.Get("X-Real-IP"))
		if rec.IP == "" {
			rec.IP = strings.TrimSpace(r.RemoteAddr)
		}
		rec.Method = strings.TrimSpace(r.Method)
		if r.URL != nil {
			rec.Path = strings.TrimSpace(r.URL.Path)
			rec.Query = strings.TrimSpace(r.URL.RawQuery)
		}
	}
	rec.Metadata = normalizeMetadata(metadata)
	Append(rec)
}

// Append は audit_log.jsonl.YYYY-MM-DD（JST 日付）に 1 行追記する。
// 旧 data/json/audit_log.jsonl が残っていれば 1 度だけ mtime 日付の新パスへリネームする。
func Append(rec Event) {
	if strings.TrimSpace(rec.Event) == "" {
		return
	}
	if strings.TrimSpace(rec.Time) == "" {
		rec.Time = time.Now().Format(time.RFC3339)
	}
	if strings.TrimSpace(rec.User) == "" {
		rec.User = "-"
	}
	rec.Result = normalizeResult(rec.Result)
	rec.Metadata = normalizeMetadata(rec.Metadata)

	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	b = append(b, '\n')

	path := writeTargetPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		log.Printf("audit: mkdir %s failed: %v", filepath.Dir(path), err)
		return
	}

	writeMu.Lock()
	defer writeMu.Unlock()
	migrateLegacyLogOnce()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		log.Printf("audit: open %s failed: %v", path, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		log.Printf("audit: write %s failed: %v", path, err)
	}
}

// writeTargetPath は現在書き込むべき audit_log.jsonl.YYYY-MM-DD 絶対パスを返す。
// HEARTDESK_AUDIT_LOG_PATH が設定されていれば（既存テスト等の後方互換用）それを優先する。
func writeTargetPath() string {
	if p := strings.TrimSpace(heartdesk.Env("HEARTDESK_AUDIT_LOG_PATH")); p != "" {
		return p
	}
	today := time.Now().In(heartdesk.JST()).Format("2006-01-02")
	return filepath.Join(LogDir(), logFilePrefix+today)
}

// LogDir は audit_log.jsonl.* を書き込む / 読む共通ディレクトリを返す。
func LogDir() string {
	if p := strings.TrimSpace(heartdesk.Env("HEARTDESK_AUDIT_LOG_DIR")); p != "" {
		return p
	}
	return heartdesk.Path(defaultLogDir)
}

// ListLogFiles は LogDir() 配下の audit_log.jsonl.YYYY-MM-DD ファイル群を日付昇順で返す。
// HEARTDESK_AUDIT_LOG_PATH が設定されているテスト用ケースでは、その単一ファイルを返す。
func ListLogFiles() ([]string, error) {
	if p := strings.TrimSpace(heartdesk.Env("HEARTDESK_AUDIT_LOG_PATH")); p != "" {
		if _, err := os.Stat(p); err == nil {
			return []string{p}, nil
		} else if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		} else {
			return nil, err
		}
	}
	matches, err := filepath.Glob(filepath.Join(LogDir(), logFilePrefix+"*"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}

// LatestLogFile は最新（日付が最大）の log ファイル絶対パスを返す。
// 1 つも存在しない場合は ("", nil) を返す。
func LatestLogFile() (string, error) {
	files, err := ListLogFiles()
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", nil
	}
	return files[len(files)-1], nil
}

func migrateLegacyLogOnce() {
	migrationOnce.Do(func() {
		oldPath := heartdesk.Path(legacyLogPath)
		info, err := os.Stat(oldPath)
		if err != nil || info.IsDir() {
			return
		}
		d := info.ModTime().In(heartdesk.JST()).Format("2006-01-02")
		newPath := filepath.Join(LogDir(), logFilePrefix+d)
		if err := os.MkdirAll(filepath.Dir(newPath), 0o750); err != nil {
			log.Printf("audit: legacy migrate mkdir failed: %v", err)
			return
		}
		// 同日のファイルが既にある場合は、旧ファイル内容を append する。
		if _, err := os.Stat(newPath); err == nil {
			if err := appendFileContents(oldPath, newPath); err != nil {
				log.Printf("audit: legacy migrate append failed: %v", err)
				return
			}
			if err := os.Remove(oldPath); err != nil {
				log.Printf("audit: legacy migrate remove old failed: %v", err)
			}
			log.Printf("audit: legacy log appended into %s", newPath)
			return
		}
		if err := os.Rename(oldPath, newPath); err != nil {
			log.Printf("audit: legacy migrate rename failed: %v", err)
			return
		}
		log.Printf("audit: legacy log migrated to %s", newPath)
	})
}

func appendFileContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func List(filter Filter) ([]Event, error) {
	migrateLegacyLogOnce()

	limit := filter.Limit
	if limit <= 0 {
		limit = defaultListLimit
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}

	files, err := ListLogFiles()
	if err != nil {
		return nil, err
	}

	user := strings.ToLower(strings.TrimSpace(filter.User))
	event := strings.ToUpper(strings.TrimSpace(filter.Event))
	result := strings.ToLower(strings.TrimSpace(filter.Result))
	query := strings.ToLower(strings.TrimSpace(filter.Query))

	rows := make([]Event, 0, limit)
	for _, fpath := range files {
		if err := readMatching(fpath, user, event, result, query, filter.From, filter.To, &rows); err != nil {
			return nil, err
		}
	}

	// 全ファイルから古い順に貯めた rows を新しい順に反転 → limit に切り詰め
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

func readMatching(fpath, user, event, result, query string, from, to *time.Time, out *[]Event) error {
	f, err := os.Open(fpath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec Event
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if !match(rec, user, event, result, query, from, to) {
			continue
		}
		*out = append(*out, rec)
	}
	return sc.Err()
}

func normalizeResult(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "success", "ok":
		return "success"
	default:
		return "fail"
	}
}

func normalizeMetadata(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		key := strings.TrimSpace(k)
		val := strings.TrimSpace(v)
		if key == "" || val == "" {
			continue
		}
		dst[key] = val
	}
	if len(dst) == 0 {
		return nil
	}
	return dst
}

func match(rec Event, user, event, result, query string, from, to *time.Time) bool {
	if user != "" && strings.ToLower(strings.TrimSpace(rec.User)) != user {
		return false
	}
	if event != "" && strings.ToUpper(strings.TrimSpace(rec.Event)) != event {
		return false
	}
	if result != "" && strings.ToLower(strings.TrimSpace(rec.Result)) != result {
		return false
	}
	if from != nil || to != nil {
		t, err := heartdesk.ParseTimestamp(rec.Time)
		if err != nil {
			return false
		}
		if from != nil && t.Before(*from) {
			return false
		}
		if to != nil && t.After(*to) {
			return false
		}
	}
	if query != "" {
		haystack := strings.ToLower(strings.Join([]string{
			rec.Event,
			rec.User,
			rec.Role,
			rec.IP,
			rec.Method,
			rec.Path,
			rec.Query,
			rec.Result,
			rec.Message,
		}, " "))
		if !strings.Contains(haystack, query) {
			return false
		}
	}
	return true
}
