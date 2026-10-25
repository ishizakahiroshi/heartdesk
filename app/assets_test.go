package app

import (
	"html/template"
	"testing"
	"testing/fstest"
)

func TestExtraTemplatesCannotOverwriteEachOther(t *testing.T) {
	standard := fstest.MapFS{"standard.html": {Data: []byte(`{{define "standard"}}standard{{end}}`)}}
	extra := fstest.MapFS{"first.html": {Data: []byte(`{{define "example"}}first{{end}}`)}, "second.html": {Data: []byte(`{{define "example"}}second{{end}}`)}}
	if _, err := parseTemplates(standard, extra, template.FuncMap{}); err == nil {
		t.Fatal("duplicate extension template silently replaced")
	}
}
