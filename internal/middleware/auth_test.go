package middleware

import (
	"net/http"
	"testing"
)

// TestCSRFMethodClassification は C-007（CSRF middleware coverage）の修正を確認する。
// safe method（GET/HEAD/OPTIONS）は CSRF 検証対象外、
// state-changing method（POST/PUT/PATCH/DELETE）は CSRF 検証対象、
// 未知 method はどちらにも該当しない（呼び出し側で 405 reject）。
func TestCSRFMethodClassification(t *testing.T) {
	tests := []struct {
		method          string
		wantSafe        bool
		wantStateChange bool
	}{
		{http.MethodGet, true, false},
		{http.MethodHead, true, false},
		{http.MethodOptions, true, false},
		{http.MethodPost, false, true},
		{http.MethodPut, false, true},
		{http.MethodPatch, false, true},
		{http.MethodDelete, false, true},
		// 未知 / 危険 method は両方 false（middleware は 405 で reject）。
		{http.MethodTrace, false, false},
		{http.MethodConnect, false, false},
		{"PROPFIND", false, false},
		{"", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			if got := isSafeMethod(tt.method); got != tt.wantSafe {
				t.Errorf("isSafeMethod(%q) = %v, want %v", tt.method, got, tt.wantSafe)
			}
			if got := isStateChangingMethod(tt.method); got != tt.wantStateChange {
				t.Errorf("isStateChangingMethod(%q) = %v, want %v", tt.method, got, tt.wantStateChange)
			}
		})
	}
}

// TestCSRFCoverageContract は C-007 の不変条件を明文化する：
// 1) safe method と state-changing method は disjoint（重複なし）
// 2) safe ∪ state-changing で既知の全 method を覆う
// 3) 未知 method はどちらも false（middleware で 405 reject される）
func TestCSRFCoverageContract(t *testing.T) {
	knownMethods := []string{
		http.MethodGet, http.MethodHead, http.MethodOptions,
		http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
	}
	for _, m := range knownMethods {
		safe := isSafeMethod(m)
		change := isStateChangingMethod(m)
		if safe && change {
			t.Errorf("method %q classified as both safe and state-changing", m)
		}
		if !safe && !change {
			t.Errorf("known method %q classified as neither safe nor state-changing", m)
		}
	}
}
