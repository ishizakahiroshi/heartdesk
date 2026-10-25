package monitor

import "net/http"

// WriteActionError writes the standard action error response.
func WriteActionError(w http.ResponseWriter, message string, status int) {
	writeActionError(w, message, status)
}

// ParseIntParam parses a nonnegative integer, returning fallback for invalid input.
func ParseIntParam(raw string, fallback int) int { return parseIntParam(raw, fallback) }

// SetDownloadHeader sets the standard download and content-type headers.
func SetDownloadHeader(w http.ResponseWriter, filename, contentType string) {
	setDownloadHeader(w, filename, contentType)
}

// CSVSafe applies the standard CSV formula prefix escaping.
func CSVSafe(value string) string { return csvSafe(value) }

// CSVBOM returns an independent copy of the UTF-8 byte order mark.
func CSVBOM() []byte { return append([]byte(nil), csvBOM...) }
