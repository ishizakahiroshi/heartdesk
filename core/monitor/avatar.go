package monitor

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

const avatarMaxBytes = 2 * 1024 * 1024 // 2MB
const avatarMultipartMaxBytes = avatarMaxBytes + 512*1024

var avatarAllowedExts = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

func avatarDir() string {
	// heartdesk ユーザーが書き込める /var/lib/heartdesk/data/avatars/ を使用
	// BASE_DIR とは別に固定パスを指定する
	return "/var/lib/heartdesk/data/avatars"
}

func avatarSafeName(username string) (string, bool) {
	name := strings.TrimSpace(username)
	if name == "" || name == "." || name == ".." {
		return "", false
	}
	if strings.ContainsAny(name, `/\`) {
		return "", false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return name, true
}

func avatarPath(username string) (string, bool) {
	username, ok := avatarSafeName(username)
	if !ok {
		return "", false
	}
	dir := avatarDir()
	for _, ext := range []string{".jpg", ".png", ".gif", ".webp"} {
		p := filepath.Join(dir, username+ext)
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

// AvatarURL はアバター画像の URL を返す。画像がなければ空文字。
func AvatarURL(monitorBase, username string) string {
	username, ok := avatarSafeName(username)
	if !ok {
		return ""
	}
	if _, ok := avatarPath(username); !ok {
		return ""
	}
	return monitorBase + "/avatar/" + url.PathEscape(username)
}

func (h *Handler) serveAvatar(w http.ResponseWriter, r *http.Request) {
	rawUsername := strings.TrimPrefix(r.URL.Path, h.routes.MonitorBase+"/avatar/")
	username, ok := avatarSafeName(rawUsername)
	if !ok {
		http.NotFound(w, r)
		return
	}
	p, ok := avatarPath(username)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, p)
}

func (h *Handler) actionUploadAvatar(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// コンテキスト（ミドルウェア経由）またはセッションCookieからユーザー取得
	username := middleware.GetUser(r.Context())
	if username == "" {
		if sess, ok := auth.DefaultSessionManager().SessionFromRequest(r); ok {
			username = sess.Username
		}
	}
	if username == "" {
		log.Printf("WARN: avatar: 未認証リクエスト")
		writeActionError(w, "未認証", http.StatusUnauthorized)
		return
	}
	var ok bool
	username, ok = avatarSafeName(username)
	if !ok {
		log.Printf("WARN: avatar: 不正なユーザー名")
		writeActionError(w, "ユーザー名が不正です", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, avatarMultipartMaxBytes)
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	if err := r.ParseMultipartForm(avatarMaxBytes + 1024); err != nil {
		log.Printf("ERROR: avatar: ParseMultipartForm error: %v", err)
		writeActionError(w, "ファイルの解析に失敗しました", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("avatar")
	if err != nil {
		log.Printf("ERROR: avatar: FormFile error: %v", err)
		writeActionError(w, "ファイルが見つかりません", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if header.Size > avatarMaxBytes {
		log.Printf("WARN: avatar: ファイルサイズ超過: %d bytes", header.Size)
		writeActionError(w, "ファイルサイズは2MB以下にしてください", http.StatusBadRequest)
		return
	}

	// Content-Type 検出
	buf := make([]byte, 512)
	n, _ := file.Read(buf)
	ct := http.DetectContentType(buf[:n])
	ext, ok := avatarAllowedExts[ct]
	if !ok {
		log.Printf("WARN: avatar: 非対応のContent-Type: %s", ct)
		writeActionError(w, "JPEG・PNG・GIF・WebPのみ対応しています", http.StatusBadRequest)
		return
	}

	dir := avatarDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("ERROR: avatar: MkdirAll(%s) error: %v", dir, err)
		writeActionError(w, "保存ディレクトリの作成に失敗しました", http.StatusInternalServerError)
		return
	}

	// 既存アバターを削除（拡張子違いのファイルが残らないよう）
	for _, oldExt := range []string{".jpg", ".png", ".gif", ".webp"} {
		_ = os.Remove(filepath.Join(dir, username+oldExt))
	}

	dest := filepath.Join(dir, username+ext)
	out, err := os.Create(dest)
	if err != nil {
		log.Printf("ERROR: avatar: os.Create(%s) error: %v", dest, err)
		writeActionError(w, "ファイルの保存に失敗しました", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	// 先頭 buf 分を書き戻してから残りをコピー
	if _, err := out.Write(buf[:n]); err != nil {
		log.Printf("ERROR: avatar: Write buf error: %v", err)
		writeActionError(w, "ファイルの書き込みに失敗しました", http.StatusInternalServerError)
		return
	}
	written, err := io.Copy(out, io.LimitReader(file, int64(avatarMaxBytes-n)+1))
	if err != nil {
		log.Printf("ERROR: avatar: io.Copy error: %v", err)
		writeActionError(w, "ファイルの書き込みに失敗しました", http.StatusInternalServerError)
		return
	}
	if int64(n)+written > avatarMaxBytes {
		_ = out.Close()
		_ = os.Remove(dest)
		log.Printf("WARN: avatar: 実ファイルサイズ超過")
		writeActionError(w, "ファイルサイズは2MB以下にしてください", http.StatusBadRequest)
		return
	}

	log.Printf("INFO: avatar: %s → %s 保存成功", username, dest)
	avatarURL := AvatarURL(h.routes.MonitorBase, username)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":         true,
		"message":    "変更しました",
		"avatar_url": avatarURL,
	})
}
