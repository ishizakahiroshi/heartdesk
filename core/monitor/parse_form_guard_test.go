package monitor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// parseFormAllowedFunc は r.ParseForm() を直接呼んでよい唯一の関数。
const parseFormAllowedFunc = "parseActionForm"

// TestNoDirectParseFormInHandlers は core/monitor のコードが r.ParseForm() を
// 直接呼んでいないことを検査する。
//
// **なぜ検査にしてあるか。** net/http の ParseForm は content-type が
// application/x-www-form-urlencoded のときしか body を読まず、multipart/form-data では
// エラーも返さずに r.PostForm を空のまま返す。画面側の JS は FormData を fetch の body に
// 渡す（= multipart で送る）ので、ParseForm だけで受けると値が 1 つも届かないのに
// 例外もログも出ない。**壊れていることに気づく手段が「画面から保存できない」しかない。**
//
// 通知設定カードでは実際に、alert_rules.json が作られず、scheduler が
// 5 分ごとに rules file not found を出し続けても誰も気づかない状態になったことがある。
//
// 新しい action handler で form を読むときは parseActionForm(r) を通すこと。
// ファイル添付を受ける経路（avatar.go）は ParseMultipartForm を直接使ってよい（対象外）。
func TestNoDirectParseFormInHandlers(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok {
					return true
				}
				if fn.Name.Name == parseFormAllowedFunc {
					return false // ここだけは直接呼んでよい
				}
				ast.Inspect(fn.Body, func(inner ast.Node) bool {
					call, ok := inner.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "ParseForm" {
						return true
					}
					pos := fset.Position(call.Pos())
					t.Errorf("%s:%d: %s() が r.ParseForm() を直接呼んでいる。"+
						"multipart/form-data では値が届かない（エラーも出ない）。"+
						"%s(r) を通すこと",
						filepath.Base(pos.Filename), pos.Line, fn.Name.Name, parseFormAllowedFunc)
					return true
				})
				return false
			})
		}
	}
}
