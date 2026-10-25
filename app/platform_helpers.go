package app

import (
	"time"

	shared "github.com/ishizakahiroshi/heartdesk/internal"
)

// JST returns the shared Japanese standard time location.
func JST() *time.Location { return shared.JST() }

// FormatDatetime preserves the supplied time's zone and adds a Japanese weekday.
func FormatDatetime(value time.Time) string { return shared.FormatDatetime(value) }

// ParseTimestamp parses the shared supported formats, using JST when no zone is supplied.
func ParseTimestamp(value string) (time.Time, error) { return shared.ParseTimestamp(value) }
