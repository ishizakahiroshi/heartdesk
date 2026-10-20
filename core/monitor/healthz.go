package monitor

import "net/http"

// HealthzHandler は死活監視用の最小エンドポイント（GET/HEAD /healthz）。
//
// 認証なしで 200 と固定の JSON を返す。バージョン・設定・パス・ホスト名などの
// 情報は一切含めない（外形監視・ロードバランサ・コンテナの死活確認専用）。
// ルーティングは main.go でセッション認証のミドルウェアを通さずに登録する。
func HealthzHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}
