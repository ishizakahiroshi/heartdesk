package monitor

import (
	"strings"
	"testing"
)

// TestRenderMarkdownHTMLEscapesRawScript は goldmark の Unsafe markdown による
// XSS の再発防止テスト。docs/infra/*.md に何らかの経路で生 <script> / <iframe> が
// 混入した場合でも、infra-doc ビューには素のタグとして出力されてはならない。
//
// goldmark のデフォルト sanitizer は raw HTML をエスケープし、無視 (omit) するか
// HTML エンティティ化する。本テストでは `<script>...</script>` が原文のまま
// 出力に残らないこと、および `</script>` の終了タグも残らないことを確認する。
func TestRenderMarkdownHTMLEscapesRawScript(t *testing.T) {
	cases := []struct {
		name string
		src  string
		bad  []string
	}{
		{
			name: "raw script tag in body",
			src:  "# title\n\n<script>alert('xss')</script>\n",
			bad:  []string{"<script>", "</script>"},
		},
		{
			name: "raw iframe tag in body",
			src:  "# title\n\n<iframe src=\"javascript:alert(1)\"></iframe>\n",
			bad:  []string{"<iframe", "</iframe>"},
		},
		{
			name: "inline event handler",
			src:  "# title\n\n<img src=x onerror=\"alert(1)\">\n",
			bad:  []string{"<img src=x onerror"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(renderMarkdownHTML([]byte(tc.src)))
			for _, needle := range tc.bad {
				if strings.Contains(got, needle) {
					t.Fatalf("renderMarkdownHTML leaked raw HTML %q in output: %q", needle, got)
				}
			}
		})
	}
}

// TestRenderMarkdownHTMLPreservesSafeMarkup は通常の Markdown が
// 正しくレンダリングされ続けることを確認 (sanitizer 強化のリグレッション防止)。
func TestRenderMarkdownHTMLPreservesSafeMarkup(t *testing.T) {
	got := string(renderMarkdownHTML([]byte("# Heading\n\n- item1\n- item2\n")))
	if !strings.Contains(got, "<h1") {
		t.Fatalf("expected <h1> in rendered markdown, got: %q", got)
	}
	if !strings.Contains(got, "<li>item1</li>") {
		t.Fatalf("expected list item rendering, got: %q", got)
	}
}
