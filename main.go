// heartdesk — エントリポイント（Monitor サーバー）
//
// 既定ではポート :8765 で起動し、以下のパスをルーティングする:
//
//	/healthz                      → 死活確認（認証なし）
//	/monitor/                     → Monitor
//	/api/monitor/...              → Monitor API
//	/api/agent/report             → Agent レポート受信（HMAC 認証）
//	/api/license/...              → Agent ライセンス検証・heartbeat
//	/static/                      → 静的ファイル（CSS/JS）
//
// 起動方法の例（サーバー上。バイナリの置き場所は任意）:
//
//	/path/to/heartdesk
//
// クロスコンパイルの例（成果物を作るので、必要なときに手動で実行する）:
//
//	GOOS=linux GOARCH=amd64 go build -o bin/heartdesk-linux-amd64 .
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/ishizakahiroshi/heartdesk/app"
	"github.com/ishizakahiroshi/heartdesk/internal"
)

const defaultListenAddr = ":8765"

// ビルド時に ldflags で注入する。未指定時は "dev" / ""。
// 例: -X main.version=v1.0.1 -X main.gitCommit=12f6a8
var version = "dev"
var gitCommit = ""
var buildID = "dev"

func buildVersionString() string {
	if version != "dev" && gitCommit != "" {
		return version + " / " + gitCommit
	}
	if version != "dev" {
		return version
	}
	if gitCommit != "" {
		return "dev / " + gitCommit
	}
	return "dev"
}

func assetVersionString() string {
	if buildID != "dev" {
		return buildID
	}
	// 開発時フォールバック（毎起動で変わる）
	return strconv.FormatInt(time.Now().Unix(), 10)
}

// resolveDataDir はデータディレクトリを返す。HEARTDESK_DATA_DIR が最優先で、
// 無ければ HEARTDESK_BASE_DIR 基準（未設定なら /var/lib/heartdesk/data）。
func resolveDataDir() string {
	if dataDir := os.Getenv("HEARTDESK_DATA_DIR"); dataDir != "" {
		return dataDir
	}
	return heartdesk.PathOrDefault("data")
}

func main() {
	opts := app.OptionsFromEnvironment()
	opts.Version = buildVersionString()
	opts.AssetVersion = assetVersionString()
	runtime, err := app.New(opts)
	if err != nil {
		log.Fatal(err)
	}
	defer runtime.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				app.ReloadConfigCache()
			}
		}
	}()
	if err := runtime.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
