package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

func TestEmbeddedFrontendScriptOrder(t *testing.T) {
	raw, err := fs.ReadFile(Templates(), "layout.html")
	if err != nil {
		t.Fatal(err)
	}
	previous := -1
	for _, marker := range []string{"/js/shared_utils.js", "/js/shared.js", "/js/card_runtime.js", "/js/card_refresh.js", "/js/card_jump.js", "{{range .CardJSModules}}", "/js/monitor_page.js"} {
		index := strings.Index(string(raw), marker)
		if index < 0 || index < previous {
			t.Fatalf("missing or reordered script: %s", marker)
		}
		previous = index
	}
}

func TestEmbeddedButtonsHaveExplicitType(t *testing.T) {
	buttons := regexp.MustCompile(`(?is)<button\b[^>]*>`)
	typeAttribute := regexp.MustCompile(`(?i)\s+type\s*=`)
	err := fs.WalkDir(Templates(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".html") {
			return nil
		}
		raw, err := fs.ReadFile(Templates(), path)
		if err != nil {
			return err
		}
		for _, tag := range buttons.FindAllString(string(raw), -1) {
			if !typeAttribute.MatchString(tag) {
				t.Errorf("%s: button has no explicit type", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestButtonTypeAttributeDoesNotAcceptDataType(t *testing.T) {
	typeAttribute := regexp.MustCompile(`(?i)\s+type\s*=`)
	for _, tag := range []string{`<button>`, `<button data-type="button">`, `<button x-type="button">`} {
		if typeAttribute.MatchString(tag) {
			t.Fatalf("non-type attribute accepted as an explicit button type: %s", tag)
		}
	}
	for _, tag := range []string{`<button type="button">`, `<button TYPE = "submit">`} {
		if !typeAttribute.MatchString(tag) {
			t.Fatalf("explicit type rejected: %s", tag)
		}
	}
}
