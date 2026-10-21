package auth

// User は users.toml のユーザー定義。
// カード表示ポリシー / 操作可否ポリシーは cards_user.toml / actions_user.toml に分離済み。
type User struct {
	ID            string   `json:"id" toml:"id"`
	Username      string   `json:"username" toml:"username"`
	Name          string   `json:"name" toml:"name"`
	PasswordHash  string   `json:"password_hash" toml:"password_hash"`
	Role          string   `json:"role" toml:"role"` // vendor_staff / tenant_admin / tenant_user
	Disabled      bool     `json:"disabled,omitempty" toml:"disabled,omitempty"`
	AccessScreens []string `json:"access_screens,omitempty" toml:"access_screens,omitempty"` // monitor / vendor（省略時はrole既定値）
}
