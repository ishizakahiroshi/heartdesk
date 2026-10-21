// Package httpx は Monitor が同一ホスト/顧客 VPS 上の内部 API
// （メール gateway / 組織同期 / チャット添付 gateway）へ
// プロキシする際の共通 HTTP クライアントを提供する。
//
// 以前は mail_gateway / nc_org_sync /
// chat_gateway がそれぞれ独自の client factory・GET/POST ヘルパを持ち、特にメール gateway は
// リクエスト毎に http.Transport を新規生成し CA ファイルを毎回ディスクから読んでいた。
// 本パッケージで以下を一元化する:
//   - Transport をパッケージ変数で 1 度だけ生成し全 client で再利用（コネクションプール有効化）
//   - レスポンスボディは必ず io.LimitReader で上限を設ける（暴走レスポンスでのメモリ枯渇防止）
//   - すべて context 経由（NewRequestWithContext）でタイムアウト/キャンセル可能
package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// DefaultMaxBodyBytes は読み取りボディの既定上限（10MiB）。
const DefaultMaxBodyBytes int64 = 10 << 20

// sharedTransport は TLS 設定を持たない（システムルート CA で検証する）共有 Transport。
// パッケージ初期化時に 1 度だけ生成し、Client() がタイムアウトのみ差し替えて再利用する。
var sharedTransport = newTransport()

// tlsTransports は TLS 設定別の Transport をキャッシュする（メール gateway の CA pool 等）。
// キーは *tls.Config のポインタ同一性（呼び出し側が起動時 1 回構築してキャッシュする前提）。
var (
	tlsTransportsMu sync.Mutex
	tlsTransports   = map[*tls.Config]*http.Transport{}
)

func newTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// Client はタイムアウトと任意の TLS 設定を持つ *http.Client を返す。
// tlsCfg が nil の場合は共有 Transport（システムルート CA 検証）を使う。
// tlsCfg 指定時は同一ポインタごとに Transport をキャッシュして再利用する。
func Client(timeout time.Duration, tlsCfg *tls.Config) *http.Client {
	if tlsCfg == nil {
		return &http.Client{Timeout: timeout, Transport: sharedTransport}
	}
	tlsTransportsMu.Lock()
	tr, ok := tlsTransports[tlsCfg]
	if !ok {
		tr = newTransport()
		tr.TLSClientConfig = tlsCfg
		tlsTransports[tlsCfg] = tr
	}
	tlsTransportsMu.Unlock()
	return &http.Client{Timeout: timeout, Transport: tr}
}

// Options は GetJSON/PostJSON/Do の共通オプション。
type Options struct {
	// BearerToken が非空なら Authorization: Bearer <token> を付与する。
	BearerToken string
	// TLSConfig が非 nil なら Client がその TLS 設定を使う（メール gateway の CA pool 等）。
	TLSConfig *tls.Config
	// Timeout はリクエストのタイムアウト（0 の場合 15s を既定とする）。
	Timeout time.Duration
	// MaxBodyBytes はレスポンスボディの読み取り上限（0 の場合 DefaultMaxBodyBytes）。
	MaxBodyBytes int64
	// Headers は追加で付与するヘッダ。
	Headers map[string]string
}

func (o Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return 15 * time.Second
}

func (o Options) maxBody() int64 {
	if o.MaxBodyBytes > 0 {
		return o.MaxBodyBytes
	}
	return DefaultMaxBodyBytes
}

// Get は GET <url> を実行し、ステータスコードと（上限付き）ボディを返す。
// status が 2xx 以外でもエラーにはせず、呼び出し側で status を見て判定する。
// 通信エラー（接続失敗等）の場合のみ err を返す。
func Get(ctx context.Context, url string, opt Options) (status int, body []byte, err error) {
	return Do(ctx, http.MethodGet, url, nil, opt)
}

// PostJSON は body を JSON エンコードして POST <url> を実行する。
func PostJSON(ctx context.Context, url string, payload any, opt Options) (status int, body []byte, err error) {
	var rdr io.Reader
	if payload != nil {
		b, mErr := json.Marshal(payload)
		if mErr != nil {
			return 0, nil, mErr
		}
		rdr = bytes.NewReader(b)
		if opt.Headers == nil {
			opt.Headers = map[string]string{}
		}
		if _, ok := opt.Headers["Content-Type"]; !ok {
			opt.Headers["Content-Type"] = "application/json"
		}
	}
	return Do(ctx, http.MethodPost, url, rdr, opt)
}

// Do は任意メソッドのリクエストを実行し、ステータスコードと上限付きボディを返す。
func Do(ctx context.Context, method, url string, reqBody io.Reader, opt Options) (status int, body []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return 0, nil, err
	}
	if opt.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+opt.BearerToken)
	}
	for k, v := range opt.Headers {
		req.Header.Set(k, v)
	}
	resp, err := Client(opt.timeout(), opt.TLSConfig).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, opt.maxBody()))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, b, nil
}

// GetJSON は GET <url> を実行し、2xx の場合 out へ JSON デコードする。
// 2xx 以外は status とボディ文字列を含むエラーを返す。
func GetJSON(ctx context.Context, url string, out any, opt Options) error {
	status, body, err := Get(ctx, url, opt)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("GET %s: status %d: %s", url, status, body)
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}
