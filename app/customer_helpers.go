package app

import (
	"net/http"

	"github.com/ishizakahiroshi/heartdesk/core/monitor"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

// ActionResponse is the standard action response shared by embedded handlers.
type ActionResponse = monitor.ActionResponse

// RequireScreen applies the shared session, screen, method and CSRF checks.
// Unknown screen names always deny access.
func RequireScreen(screen string) func(http.Handler) http.Handler {
	if auth.NormalizeScreen(screen) == "" {
		return func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "403 Forbidden: アクセス権限がありません", http.StatusForbidden)
			})
		}
	}
	return middleware.RequireScreen(auth.Screen(screen))
}

// WriteActionError writes the standard action error response.
func WriteActionError(w http.ResponseWriter, message string, status int) {
	monitor.WriteActionError(w, message, status)
}

// ParseIntParam parses a nonnegative integer, returning fallback for invalid input.
func ParseIntParam(raw string, fallback int) int { return monitor.ParseIntParam(raw, fallback) }

// SetDownloadHeader sets the standard download and content-type headers.
func SetDownloadHeader(w http.ResponseWriter, filename, contentType string) {
	monitor.SetDownloadHeader(w, filename, contentType)
}

// CSVSafe applies the standard CSV formula prefix escaping.
func CSVSafe(value string) string { return monitor.CSVSafe(value) }

// CSVBOM returns an independent copy of the UTF-8 byte order mark.
func CSVBOM() []byte { return monitor.CSVBOM() }
