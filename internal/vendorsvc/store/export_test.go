package store

import "time"

// ParseStoreTimeForTest は parseStoreTime のテスト用エクスポート。
// store パッケージ外（store_test）から参照するためだけに存在する。
func ParseStoreTimeForTest(s string) time.Time {
	return parseStoreTime(s)
}
