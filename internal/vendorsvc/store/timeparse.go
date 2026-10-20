package store

import (
	"log"
	"strings"
	"time"
)

// storeTimeLayout は store が新規書き込み時に使う時刻文字列の形式（ISO8601・UTC）。
const storeTimeLayout = "2006-01-02T15:04:05Z"

// storeTimeFallbackLayouts は parseStoreTime が順に試すフォールバック形式。
// SQLite の DEFAULT (datetime('now')) や旧 INSERT の datetime('now') リテラルが
// 返す "YYYY-MM-DD HH:MM:SS"（半角スペース区切り・Z 無し）を受けるための互換層。
// 先頭が正規（Go 側で書いた新規データ）、続いて SQLite 既定フォーマット。
var storeTimeFallbackLayouts = []string{
	storeTimeLayout,       // 2026-06-15T16:36:05Z（Go 側で書いた新規データ）
	"2006-01-02 15:04:05", // SQLite datetime('now') 既定（DEFAULT 経由の既存データ）
	"2006-01-02T15:04:05", // 念のため T 区切り・Z 無し
	time.RFC3339,          // タイムゾーン付き（将来用）
	time.RFC3339Nano,      // ナノ秒付き（将来用）
}

// nowStoreTime は INSERT/UPDATE 時に DB へ書き込む現在時刻文字列を返す。
// 旧コードで散在していた datetime('now') リテラルを置き換えるためのヘルパ。
// 既存データとの互換性のため、書き込みフォーマットは storeTimeLayout に統一する。
func nowStoreTime() string {
	return time.Now().UTC().Format(storeTimeLayout)
}

// parseStoreTime は DB から取得した時刻文字列をパースする。
// 空文字はゼロ値（エラーなし）を返す。複数の保存形式（Go 側の ISO8601 と
// SQLite の datetime('now') 既定の "YYYY-MM-DD HH:MM:SS" 両方）に対応し、
// すべての形式で失敗したときのみゼロ値を返しつつ log で可視化する。
func parseStoreTime(s string) time.Time {
	if strings.TrimSpace(s) == "" {
		return time.Time{}
	}
	for _, layout := range storeTimeFallbackLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	log.Printf("store: time.Parse failed for %q: no matching layout", s)
	return time.Time{}
}
