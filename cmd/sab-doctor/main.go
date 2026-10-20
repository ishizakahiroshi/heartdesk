package main

import (
	"fmt"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var buttonTagRe = regexp.MustCompile(`(?is)<button\b[^>]*>`)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "env" {
		runEnvCheck()
		return
	}

	tenant := os.Getenv("SAB_TENANT_ID")
	if os.Getenv("SAB_CONFIG_DIR") == "" {
		if _, err := os.Stat("config/config.toml"); err == nil {
			_ = os.Setenv("SAB_CONFIG_DIR", "config")
		} else if _, err := os.Stat("../../config/config.toml"); err == nil {
			_ = os.Setenv("SAB_CONFIG_DIR", "../../config")
		}
	}
	cfg, err := config.LoadAppConfigForTenant(tenant)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load failed: %v\n", err)
		os.Exit(1)
	}
	if err := navmeta.ValidateCardMetaConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "cards.meta validation failed: %v\n", err)
		os.Exit(1)
	}
	wd, _ := os.Getwd()
	templatesDir := filepath.Join(wd, "web", "templates")
	cardsJSDir := filepath.Join(wd, "web", "static", "js", "cards")
	if err := navmeta.ValidateTemplateAndJSModules(templatesDir, cardsJSDir); err != nil {
		fmt.Fprintf(os.Stderr, "template/js validation failed: %v\n", err)
		os.Exit(1)
	}
	if err := validateFrontendContracts(wd); err != nil {
		fmt.Fprintf(os.Stderr, "frontend contract validation failed: %v\n", err)
		os.Exit(1)
	}
	if err := validateTrackedArtifacts(wd); err != nil {
		fmt.Fprintf(os.Stderr, "tracked artifact validation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("doctor ok")
}

func runEnvCheck() {
	requiredEnvs := []string{"SAB_BASE_DIR", "SAB_CONFIG_DIR", "SAB_TENANT_ID"}
	ok := true
	for _, e := range requiredEnvs {
		v := os.Getenv(e)
		if v == "" {
			fmt.Printf("NG: %s is not set\n", e)
			ok = false
		} else {
			fmt.Printf("OK: %s=%s\n", e, v)
		}
	}
	if !ok {
		os.Exit(1)
	}
}

func validateFrontendContracts(wd string) error {
	layoutRaw, err := os.ReadFile(filepath.Join(wd, "web", "templates", "layout.html"))
	if err != nil {
		return err
	}
	layout := string(layoutRaw)
	required := []string{
		`IH_COLLAPSE_KEY = "sab.monitor.collapsed.v1"`,
		`IH_COLLAPSE_LEGACY_KEY = "nab.monitor.collapsed.v1"`,
		`IH_SIDENAV_SERVER_TREE_KEY = "sab.monitor.sidenav.server_tree.v1"`,
		`IH_SIDENAV_SERVER_TREE_LEGACY_KEY = "nab.monitor.sidenav.server_tree.v1"`,
		`IH_SIDENAV_ORDER_KEY = "sab.monitor.sidenav.order.v1"`,
	}
	for _, needle := range required {
		if !strings.Contains(layout, needle) {
			return fmt.Errorf("layout.html missing %q", needle)
		}
	}
	sharedRaw, err := os.ReadFile(filepath.Join(wd, "web", "static", "js", "shared.js"))
	if err != nil {
		return err
	}
	shared := string(sharedRaw)
	for _, needle := range []string{"COLLAPSE_LEGACY_KEY", "SIDENAV_SERVER_TREE_LEGACY_KEY"} {
		if !strings.Contains(shared, needle) {
			return fmt.Errorf("shared.js missing legacy localStorage migration marker %q", needle)
		}
	}
	order := []string{"/js/shared_utils.js", "/js/shared.js", "/js/card_runtime.js", "/js/card_refresh.js", "/js/card_jump.js", "{{range .CardJSModules}}", "/js/monitor_page.js"}
	prev := -1
	for _, needle := range order {
		idx := strings.Index(layout, needle)
		if idx < 0 {
			return fmt.Errorf("layout.html missing script marker %q", needle)
		}
		if idx < prev {
			return fmt.Errorf("layout.html script order is invalid around %q", needle)
		}
		prev = idx
	}
	if err := validateButtonTypes(filepath.Join(wd, "web", "templates")); err != nil {
		return err
	}
	return nil
}

func validateButtonTypes(templatesDir string) error {
	return filepath.Walk(templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info == nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".html") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, loc := range buttonTagRe.FindAllStringIndex(string(raw), -1) {
			tag := string(raw[loc[0]:loc[1]])
			if !strings.Contains(strings.ToLower(tag), "type=") {
				rel, _ := filepath.Rel(templatesDir, path)
				return fmt.Errorf("%s has button without explicit type: %s", filepath.ToSlash(rel), compactTag(tag))
			}
		}
		return nil
	})
}

func compactTag(tag string) string {
	tag = strings.Join(strings.Fields(tag), " ")
	if len(tag) > 160 {
		return tag[:157] + "..."
	}
	return tag
}

func validateTrackedArtifacts(wd string) error {
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	cmd := exec.Command("git", "ls-files")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var bad []string
	for _, line := range strings.Split(string(out), "\n") {
		path := strings.TrimSpace(filepath.ToSlash(line))
		if path == "" {
			continue
		}
		if strings.HasPrefix(path, "src/sab/bin/") ||
			strings.HasPrefix(path, "NEXTCLOUD_SOURCES/") ||
			strings.HasSuffix(path, ".local.md") ||
			strings.HasSuffix(path, ".exe") ||
			strings.HasSuffix(path, ".test") {
			bad = append(bad, path)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("generated/local files are tracked: %s", strings.Join(bad, ", "))
	}
	return nil
}
