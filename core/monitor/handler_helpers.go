package monitor

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
)

func resolveInitialFromName(name string) string {
	for _, r := range name {
		return strings.ToUpper(string(r))
	}
	return "?"
}

// ---- ヘルパー ----

// resolveDisplayName はユーザー名から表示名（Name）を返す。見つからない場合はusernameそのまま。
func resolveDisplayName(username string) string {
	if username == "" {
		return ""
	}
	u, ok := auth.DefaultStore().GetUser(username)
	if !ok || u.Name == "" {
		return username
	}
	return u.Name
}

// resolveInitial は表示名の先頭1文字（ルーン）を大文字で返す。
func resolveInitial(username string) string {
	name := resolveDisplayName(username)
	for _, r := range name {
		return strings.ToUpper(string(r))
	}
	return "?"
}

// parseIntParam はクエリパラメータ文字列を非負 int に変換する。
// 空文字・パース不能・負値・オーバーフローのときは defaultVal を返す。
// strconv.Atoi を使うことで "0" を正しく 0 として扱い（旧実装は 0 を defaultVal に
// していたため index/dow=0 が無視されていた）、巨大入力でのオーバーフローも防ぐ。
func parseIntParam(s string, defaultVal int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return defaultVal
	}
	return n
}

func writeActionOK(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ActionResponse{OK: true, Message: msg})
}

func writeActionError(w http.ResponseWriter, msg string, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ActionResponse{OK: false, Message: msg})
}

func normalizeCardModes(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(src))
	for cardID, mode := range src {
		id := strings.TrimSpace(cardID)
		if id == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case "full":
			out[id] = "full"
		case "summary":
			out[id] = "summary"
		case "hidden":
			out[id] = "hidden"
		}
	}
	return out
}

func normalizeChildCardModes(src map[string]map[string]string) map[string]map[string]string {
	if len(src) == 0 {
		return map[string]map[string]string{}
	}
	out := make(map[string]map[string]string)
	for parentID, children := range src {
		parent := strings.TrimSpace(parentID)
		if parent == "" || len(children) == 0 {
			continue
		}
		childOut := normalizeCardModes(children)
		if len(childOut) == 0 {
			continue
		}
		out[parent] = childOut
	}
	return out
}

func jsonMapJS(m map[string]string) template.JS {
	if len(m) == 0 {
		return template.JS("{}")
	}
	return template.JS(safeJSON(m))
}

func jsonNestedMapJS(m map[string]map[string]string) template.JS {
	if len(m) == 0 {
		return template.JS("{}")
	}
	return template.JS(safeJSON(m))
}

// ---- Services アクション ----
