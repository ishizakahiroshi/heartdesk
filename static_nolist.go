package main

import (
	"io/fs"
	"net/http"
)

// noListFileSystem は http.FileServer に渡すファイルシステムの包みで、ディレクトリを開こうとすると
// 「無い」を返す。素の FileServer はディレクトリを開くと中身の一覧（/static/js/ なら全ファイル名）を返してしまう。
// ファイルへのリクエストはそのまま通す。
type noListFileSystem struct {
	http.FileSystem
}

func (n noListFileSystem) Open(name string) (http.File, error) {
	f, err := n.FileSystem.Open(name)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.IsDir() {
		_ = f.Close()
		return nil, fs.ErrNotExist
	}
	return f, nil
}
