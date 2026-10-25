package app_test

import (
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/app"
)

func TestPlatformTimeHelpers(t *testing.T) {
	_, offset := time.Date(2026, 10, 25, 0, 0, 0, 0, app.JST()).Zone()
	if offset != 9*3600 {
		t.Fatalf("JST offset=%d", offset)
	}
	input := time.Date(2026, 10, 25, 12, 34, 56, 0, time.UTC)
	if got := app.FormatDatetime(input); got != "2026-10-25(日) 12:34:56" {
		t.Fatalf("formatted=%q", got)
	}
	for _, item := range []struct{ raw, expected string }{{"2026-10-25T03:34:56Z", "2026-10-25T03:34:56Z"}, {" 2026-10-25T12:34:56 ", "2026-10-25T12:34:56+09:00"}, {"2026-10-25 12:34:56", "2026-10-25T12:34:56+09:00"}, {"2026-10-25T12:34:56+02:00", "2026-10-25T12:34:56+02:00"}} {
		got, err := app.ParseTimestamp(item.raw)
		if err != nil || got.Format(time.RFC3339) != item.expected {
			t.Fatalf("ParseTimestamp(%q)=%v %v", item.raw, got, err)
		}
	}
	for _, item := range []struct{ raw, message string }{{" ", "empty timestamp"}, {"bad", "unparseable timestamp: bad"}} {
		got, err := app.ParseTimestamp(item.raw)
		if err == nil || !got.IsZero() || err.Error() != item.message {
			t.Fatalf("invalid parse=%v %v", got, err)
		}
	}
}
