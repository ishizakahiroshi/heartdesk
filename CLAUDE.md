<!-- このファイルはプロジェクト固有ルールのみを書く。個人/グローバル AI ルール
（言語・確認スタイル・出力フォーマット等）は各 AI ツールのグローバル設定へ。
fresh public clone でも有効な内容に保つこと。 -->

# heartdesk 開発ガイド

> **このファイルは索引であって本文ではない。** 全 AI セッションで全文がロードされるので、
> ルールの本文はここへ書かず、破る人が必ず開く場所（コード・検査スクリプト・skill・guide・台帳）へ置き、
> ここには索引の 1 行だけを残す。新しいルールを足す前に既存の CLAUDE.md・skill・guide・台帳を検索し、
> 正本が既にあれば参照だけにする。詳細は下記「設計原則の索引」。

## プロジェクト概要

heartdesk は、複数のサーバーを 1 つの画面で見る Go 製のダッシュボードサーバー。Monitor の画面（サーバーごとのカード）、scheduler、認証と権限、通知、テナント管理と Vendor Console を持つ。報告を送る側（Agent）は姉妹の OSS [heartpost](https://github.com/ishizakahiroshi/heartpost)。ライセンスは Apache-2.0。

2026-10-20 に、個人の用途で作った監視基盤 sab の汎用部分を切り出して作った（sab 側は動いたまま。sab は heartdesk を import せず、コードを複製した状態から始まっている）。**公開前・作業中。起動と画面の確認はまだしていない**（`README.md` の Status 節）。

## やらないこと（スコープ外）

- 特定の会社・特定の運用のために作った機能（Nextcloud と社内システムの連携ハブ、メール gateway、組織同期、チャット連携など）。sab に残してあり、heartdesk には入れない
- 顧客・会社の固有名、実在のホスト名・IP・メールアドレスをコードやテストの例に書くこと（例は `alpha`・`host-1`・`example.com`・`203.0.113.x`）
- 宣伝用のドメイン・SNS アカウント（作らない方針。2026-10-20）

## 技術スタック

| 項目 | 内容 |
|---|---|
| 言語 | Go 1.25（`go.mod`）。cgo なし |
| 保存 | SQLite（`modernc.org/sqlite`）と JSON・CSV |
| 画面 | HTML テンプレートと素の JS・CSS（`web/`。バイナリに埋め込む） |
| 依存 | heartpost（署名と報告の形式）、`BurntSushi/toml`、`goldmark`、`maxminddb-golang`、`x/crypto` |

## ディレクトリ構成

- `main.go` — 起動の処理（設定の読み込み・ルーティング・HTTP サーバー）
- `internal/` — 共通のパッケージ（config・routing・auth・authz・alerts・scheduler・vendorsvc・license・navmeta ほか）
- `core/monitor/` — Monitor の本体（HTTP ハンドラ・カードの API・Agent の報告の受信）
- `core/vendor_console/` — Vendor Console の出力と鍵の入れ替え
- `cmd/` — CLI（alerts・sab-doctor・sab-scheduler）
- `web/` — 画面（templates・static）
- `docs/local/` — 作業ノート（git 無視。移植の記録 `port-notes_*.md` を含む）

## 主要コマンド

- 型検査: `go vet ./...`
- コンパイルの確認（成果物なし）: `go build ./...`
- テスト: `go test ./...`
- CLAUDE.md の検査: `node scripts/check-claude-md.mjs`

## 設計原則の索引（本文は正本にある）

| ルール | 正本（本文はここ） | 機械検査 |
|---|---|---|
| 秘密の形の文字列を commit しない（既知の見本の値だけ許可） | `.gitleaks.toml` | pre-commit の gitleaks・`.github/workflows/gitleaks.yml` |
| 固有名詞・私的パスを公開物へ入れない | `scripts/secrets-scan.mjs` | pre-commit・`.github/workflows/secrets-scan.yml` |
| CLAUDE.md を太らせない | `scripts/check-claude-md.mjs` | pre-commit |
| 旧名（`SAB_*` の環境変数・パス・カード ID・cookie 名など）の付け替えは未了 | `README.md` の Status 節 | なし（まとめて行う予定） |

**新しいルールを足す前に、まずこの表に 1 行足せる形にできないかを考える。** できないもの
（機械検査も、決まったファイルも無いもの）だけが本文を持ってよい。

## AI 作業共通ルール

ビルド・コミット禁止、secrets-scan 責務、plan/bugfix/pending md の作成ルール等の AI 作業共通ルールは、各利用者のグローバル AI 設定に従う（作者環境の例: `~/.claude/CLAUDE.md` および `~/.claude/guides/`）。

- sab から複製したコードに、顧客の固有名が混ざっていないかを、commit の前に確かめる（sab 側の検査の道具は作者環境にある。ここでは `scripts/secrets-scan.mjs` と gitleaks が止める）

## Obsidian artifacts

If `docs/obsidian/README.md` exists, use it as an index for related knowledge artifacts.
Use the repository-relative `docs/obsidian` entry. Do not write to a central absolute
path and do not silently fall back to `docs/local` when the entry is missing.

## secrets-scan（このリポジトリの配線）

書く瞬間の責務（固有名詞の一般化・fixture は合成データ等）は上記「AI 作業共通ルール」の参照先に従う。このリポジトリ固有の配線は以下:

- scanner: `scripts/secrets-scan.mjs`（手動実行: `node scripts/secrets-scan.mjs --staged --block`）
- layer 2: `.githooks/pre-commit`（`git config core.hooksPath .githooks` で有効化。gitleaks → secrets-scan → check-claude-md の順）/ layer 3: `.github/workflows/secrets-scan.yml` と `.github/workflows/gitleaks.yml` / layer 4: release ゲート
- env (full coverage に必要・未設定なら構造 regex のみで継続): `KB_ROOT` / `FAMILY_ROOT`。設定詳細は `scripts/secrets-scan.mjs` の冒頭コメント

## 関連ドキュメント

| 項目 | パス |
|---|---|
| ユーザー向け README | `README.md` |
| Codex/他 AI 用入口 | `AGENTS.md` |
| ローカル作業ノート（非公開） | `docs/local/`（存在する場合） |
| Obsidian knowledge artifacts | `docs/obsidian/`（存在する場合。作業キューではない） |
