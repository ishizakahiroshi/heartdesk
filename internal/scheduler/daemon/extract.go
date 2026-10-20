package daemon

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

const (
	extractSourceLog      = "/var/www/nextcloud/data/nextcloud.log"
	extractBaseDir        = "/var/lib/heartdesk/data/nc_extract"
	extractStateFile      = extractBaseDir + "/extract_state.json"
	extractLoginFile      = extractBaseDir + "/login_events.jsonl"
	extractContextFile    = extractBaseDir + "/login_context.jsonl"
	extractSecurityFile   = extractBaseDir + "/security_events.jsonl"
	extractLockoutFile    = extractBaseDir + "/lockout_events.jsonl"
	extractHeartbeatFile  = extractBaseDir + "/extract_last.csv"
	extractMaxLinesPerRun = 200000
	extractAccessLog      = "/var/log/nginx/access.log"
	extractNC4xxDir       = "/var/lib/heartdesk/data/json/nc4xx"
	extractNC4xxMaxLines  = 200000
)

type extractState struct {
	Inode       uint64 `json:"inode"`
	Offset      int64  `json:"offset"`
	NC4xxInode  uint64 `json:"nc4xx_inode"`
	NC4xxOffset int64  `json:"nc4xx_offset"`
	UpdatedAt   string `json:"updated_at"`
}

type ncEvent map[string]interface{}

type nc4xxRecord struct {
	Ts     string `json:"ts"`
	IP     string `json:"ip"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	UA     string `json:"ua"`
}

// ExtractNextcloudEvents は nextcloud.log / nginx access.log を読み込み、
// ログイン・セキュリティ・lockout・4xx イベントを JSONL に抽出する。
// 旧 cmd/extract 相当。
func ExtractNextcloudEvents(ctx context.Context, cfg *config.SchedulerConfig) error {
	if err := os.MkdirAll(extractBaseDir, 0o770); err != nil {
		return fmt.Errorf("failed to create dir: %s: %w", extractBaseDir, err)
	}

	fh, err := os.Open(extractSourceLog)
	if err != nil {
		return fmt.Errorf("failed to open source log: %s: %w", extractSourceLog, err)
	}
	defer fh.Close()

	state := &extractState{Offset: 0, NC4xxOffset: 0}
	if data, err := os.ReadFile(extractStateFile); err == nil {
		_ = json.Unmarshal(data, state)
	}
	if state.Offset < 0 {
		state.Offset = 0
	}
	if state.NC4xxOffset < 0 {
		state.NC4xxOffset = 0
	}

	st, _ := fh.Stat()
	inode := extractInode(st)
	size := st.Size()
	offset := state.Offset

	if state.Inode != inode || offset > size {
		offset = 0
	}
	if offset > 0 {
		fh.Seek(offset, io.SeekStart)
	}

	processed := 0
	jsonErrors := 0
	loginCount := 0
	contextCount := 0
	securityCount := 0
	lockoutCount := 0
	lexiconIgnored := 0

	handles := make(map[string]*os.File)
	defer func() {
		for _, h := range handles {
			h.Close()
		}
	}()

	scanner := bufio.NewScanner(fh)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() && processed < extractMaxLinesPerRun {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		processed++

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var data ncEvent
		if err := json.Unmarshal([]byte(line), &data); err != nil {
			jsonErrors++
			continue
		}

		msg := strings.ToLower(extractToStr(data["message"]))
		url := extractToStr(data["url"])
		reqID := strings.TrimSpace(extractToStr(data["reqId"]))
		hasException := data["exception"] != nil
		level := extractToInt(data["level"])

		isLogin := extractDetectLoginResult(extractToStr(data["message"])) != "" && !extractIsSyncURL(url)
		isBruteforce := strings.Contains(msg, "bruteforce attempt")
		isLockout := strings.Contains(msg, "too many consecutive failed login attempts")
		isLexiconNoise := strings.Contains(msg, "not defined in the config lexicon")

		if isLogin {
			if extractAppendJSON(handles, extractLoginFile, data) {
				loginCount++
			}
		}
		if isLockout {
			if extractAppendJSON(handles, extractLockoutFile, data) {
				lockoutCount++
			}
		}
		if reqID != "" && (isLogin || isBruteforce || hasException) {
			if extractAppendJSON(handles, extractContextFile, data) {
				contextCount++
			}
		}
		if level >= 2 {
			if isLexiconNoise {
				lexiconIgnored++
			} else {
				if extractAppendJSON(handles, extractSecurityFile, data) {
					securityCount++
				}
			}
		}
	}

	newOffset, _ := fh.Seek(0, io.SeekCurrent)

	nc4xxCount := 0
	nc4xxInode := state.NC4xxInode
	{
		os.MkdirAll(extractNC4xxDir, 0o770)

		if fhA, err := os.Open(extractAccessLog); err == nil {
			stA, _ := fhA.Stat()
			inodeA := extractInode(stA)
			sizeA := stA.Size()
			offsetA := state.NC4xxOffset

			if state.NC4xxInode != inodeA || offsetA > sizeA {
				offsetA = 0
			}
			if offsetA > 0 {
				fhA.Seek(offsetA, io.SeekStart)
			}

			scannerA := bufio.NewScanner(fhA)
			scannerA.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			processedA := 0
			reNginx := regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+) [^"]*" (\d{3}) \d+ "[^"]*" "([^"]*)"$`)

			for scannerA.Scan() && processedA < extractNC4xxMaxLines {
				if ctx.Err() != nil {
					fhA.Close()
					return ctx.Err()
				}
				processedA++

				lineA := strings.TrimRight(scannerA.Text(), "\n")
				if lineA == "" {
					continue
				}
				if !strings.Contains(lineA, "/nextcloud/") {
					continue
				}
				m := reNginx.FindStringSubmatch(lineA)
				if m == nil {
					continue
				}
				status, _ := strconv.Atoi(m[5])
				if status < 400 || status >= 500 || status == 401 {
					continue
				}
				path := m[4]
				if idx := strings.Index(path, "?"); idx >= 0 {
					path = path[:idx]
				}
				if !strings.HasPrefix(path, "/nextcloud/") {
					continue
				}
				ts := extractParseNginxTimestamp(m[2])
				record := nc4xxRecord{
					Ts:     ts,
					IP:     m[1],
					Method: m[3],
					Path:   path,
					Status: status,
					UA:     m[6],
				}
				nc4xxFile := filepath.Join(extractNC4xxDir, fmt.Sprintf("nc4xx_%s.jsonl", time.Now().Format("200601")))
				extractAppendJSON(handles, nc4xxFile, record)
				nc4xxCount++
			}

			newOffsetA, _ := fhA.Seek(0, io.SeekCurrent)
			nc4xxInode = inodeA
			state.NC4xxOffset = extractMax(0, newOffsetA)
			fhA.Close()
		}
	}

	newState := extractState{
		Inode:       inode,
		Offset:      extractMax(0, newOffset),
		NC4xxInode:  nc4xxInode,
		NC4xxOffset: state.NC4xxOffset,
		UpdatedAt:   time.Now().Format(time.RFC3339),
	}
	if data, err := json.Marshal(newState); err == nil {
		tmpFile := extractStateFile + ".tmp"
		os.WriteFile(tmpFile, data, 0o660)
		os.Rename(tmpFile, extractStateFile)
		os.Chmod(extractStateFile, 0o660)
	}

	extractWriteHeartbeat(extractHeartbeatFile, processed, loginCount, contextCount, securityCount, lockoutCount, lexiconIgnored, jsonErrors, nc4xxCount)

	return nil
}

func extractDetectLoginResult(message string) string {
	msg := strings.ToLower(message)
	if strings.Contains(msg, "login successful") ||
		strings.Contains(msg, "login succeeded") ||
		strings.Contains(msg, "successful login") {
		return "success"
	}
	if strings.Contains(msg, "login failed") ||
		strings.Contains(msg, "login failure") ||
		strings.Contains(msg, "failed login") {
		return "fail"
	}
	return ""
}

func extractIsSyncURL(url string) bool {
	if url == "" {
		return false
	}
	return strings.Contains(url, "/remote.php/") ||
		strings.Contains(url, "/ocs/v1.php/") ||
		strings.Contains(url, "/ocs/v2.php/") ||
		strings.Contains(url, "/apps/dav/")
}

func extractAppendJSON(handles map[string]*os.File, path string, obj interface{}) bool {
	h, exists := handles[path]
	if !exists {
		var err error
		h, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o660)
		if err != nil {
			return false
		}
		handles[path] = h
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return false
	}
	_, err = h.Write(append(data, '\n'))
	return err == nil
}

func extractParseNginxTimestamp(ts string) string {
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", ts)
	if err != nil {
		return ts
	}
	return t.Format(time.RFC3339)
}

func extractWriteHeartbeat(path string, processed, login, context, security, lockout, lexiconIgnored, jsonErrors, nc4xx int) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o660)
	if err != nil {
		log.Printf("extract: heartbeat open %s failed: %v", path, err)
		return
	}
	defer f.Close()

	info, _ := os.Stat(path)
	if info == nil || info.Size() == 0 {
		if _, err := f.WriteString("timestamp,processed,login,context,security,lockout,lexicon_ignored,json_errors,nc4xx\n"); err != nil {
			log.Printf("extract: heartbeat header write %s failed: %v", path, err)
		}
	}

	w := csv.NewWriter(f)
	if err := w.Write([]string{
		time.Now().Format(time.RFC3339),
		strconv.Itoa(processed),
		strconv.Itoa(login),
		strconv.Itoa(context),
		strconv.Itoa(security),
		strconv.Itoa(lockout),
		strconv.Itoa(lexiconIgnored),
		strconv.Itoa(jsonErrors),
		strconv.Itoa(nc4xx),
	}); err != nil {
		log.Printf("extract: heartbeat write %s failed: %v", path, err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		log.Printf("extract: heartbeat flush %s failed: %v", path, err)
	}
}

// extractInode は OS 依存実装に分離した（extract_inode_linux.go / extract_inode_other.go）。
// Linux では実 inode を返し、ログローテート検出（state.Inode != inode）を機能させる。

func extractToStr(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func extractToInt(v interface{}) int {
	if v == nil {
		return 0
	}
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

func extractMax(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
