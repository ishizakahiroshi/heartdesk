// Package web owns the embedded standard templates and static files.
package web

import (
	"embed"
	"io/fs"
)

//go:embed templates/*.html static
var assets embed.FS

func Templates() fs.FS { sub, _ := fs.Sub(assets, "templates"); return sub }
func Static() fs.FS    { sub, _ := fs.Sub(assets, "static"); return sub }
