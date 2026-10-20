package monitor

import (
	"strings"
	"testing"
)

func TestSafeJSONEscapesScriptLineSeparators(t *testing.T) {
	got := safeJSON(map[string]string{
		"name": "before\u2028middle\u2029after",
	})
	if strings.Contains(got, "\u2028") || strings.Contains(got, "\u2029") {
		t.Fatalf("safeJSON left raw JS line separators: %q", got)
	}
	if !strings.Contains(got, `\u2028`) || !strings.Contains(got, `\u2029`) {
		t.Fatalf("safeJSON did not emit escaped line separators: %q", got)
	}
}

func TestTemplateJSONHelpersUseSafeJSON(t *testing.T) {
	js := jsonMapJS(map[string]string{"display": "a\u2028b\u2029c"})
	raw := string(js)
	if strings.Contains(raw, "\u2028") || strings.Contains(raw, "\u2029") {
		t.Fatalf("jsonMapJS left raw JS line separators: %q", raw)
	}
	if !strings.Contains(raw, `\u2028`) || !strings.Contains(raw, `\u2029`) {
		t.Fatalf("jsonMapJS did not emit escaped line separators: %q", raw)
	}
}
