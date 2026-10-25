package app

import (
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/web"
)

type combinedFS struct{ standard, extra fs.FS }

func (f combinedFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, fs.ErrInvalid
	}
	v, err := f.standard.Open(name)
	if err == nil || !errors.Is(err, fs.ErrNotExist) || f.extra == nil {
		return v, err
	}
	return f.extra.Open(name)
}

func validateExtra(standard, extra fs.FS) error {
	if extra == nil {
		return nil
	}
	return fs.WalkDir(extra, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !fs.ValidPath(name) || strings.Contains(name, "\\") {
			return fs.ErrInvalid
		}
		if d.IsDir() {
			return nil
		}
		if _, err := fs.Stat(standard, name); err == nil {
			return fmt.Errorf("app: asset collision %q", name)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	})
}
func validateAssets(templates, static fs.FS) error {
	if err := validateExtra(web.Templates(), templates); err != nil {
		return err
	}
	return validateExtra(web.Static(), static)
}
func combineStatic(standard, extra fs.FS) (fs.FS, error) {
	if err := validateExtra(standard, extra); err != nil {
		return nil, err
	}
	return combinedFS{standard, extra}, nil
}

func parseTemplates(standard, extra fs.FS, funcs template.FuncMap) (*template.Template, error) {
	base, err := template.New("").Funcs(funcs).ParseFS(standard, "*.html")
	if err != nil {
		return nil, err
	}
	if extra == nil {
		return base, nil
	}
	addon := template.New("").Funcs(funcs)
	err = fs.WalkDir(extra, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(name, ".html") {
			return nil
		}
		body, err := fs.ReadFile(extra, name)
		if err != nil {
			return err
		}
		one, err := template.New(name).Funcs(funcs).Parse(string(body))
		if err != nil {
			return err
		}
		for _, t := range one.Templates() {
			if addon.Lookup(t.Name()) != nil {
				return fmt.Errorf("app: duplicate extension template %q", t.Name())
			}
		}
		for _, t := range one.Templates() {
			if t.Tree != nil {
				if _, err := addon.AddParseTree(t.Name(), t.Tree); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, t := range addon.Templates() {
		if t.Name() == "" {
			continue
		}
		if base.Lookup(t.Name()) != nil {
			return nil, fmt.Errorf("app: template collision %q", t.Name())
		}
	}
	for _, t := range addon.Templates() {
		if t.Tree != nil {
			if _, err = base.AddParseTree(t.Name(), t.Tree); err != nil {
				return nil, err
			}
		}
	}
	return base, nil
}

type noListFileSystem struct{ http.FileSystem }

func (n noListFileSystem) Open(name string) (http.File, error) {
	f, err := n.FileSystem.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.IsDir() {
		_ = f.Close()
		return nil, fs.ErrNotExist
	}
	return f, nil
}
