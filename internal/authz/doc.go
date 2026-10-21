// Package authz はカード表示ポリシーと操作権限ポリシーを読み込み、
// tenant > agent > user の継承順でマージするレイヤー。
//
// 扱うファイル（いずれも config/ 配下）:
//   - cards_tenants.toml   … テナント/エージェント標準のカード表示
//   - cards_user.toml      … ユーザー単位の追加非表示（hide only）
//   - actions_tenants.toml … テナント/エージェント標準の操作可否
//   - actions_user.toml    … ユーザー単位の追加禁止（deny only）
//
// 方針:
//   - マージ順は tenant -> agent -> user で、user は常に「弱める方向だけ」
//   - 上位で隠したもの/禁止したものを user で復活させることはできない
//
// 読み込みとマージ（Resolve）を提供する。Resolve は auth/session.go が
// session 生成時に呼ぶ。
package authz
