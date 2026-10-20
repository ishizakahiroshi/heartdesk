package main

import (
	"path/filepath"
	"testing"
)

func TestValidateFrontendContracts(t *testing.T) {
	wd := filepath.Clean(filepath.Join("..", ".."))
	if err := validateFrontendContracts(wd); err != nil {
		t.Fatalf("validateFrontendContracts: %v", err)
	}
}
