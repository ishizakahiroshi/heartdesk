package main

import (
	"fmt"
	"github.com/ishizakahiroshi/heartdesk/internal"
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

	tenant := os.Getenv("HEARTDESK_TENANT_ID")
	if os.Getenv("HEARTDESK_CONFIG_DIR") == "" {
		if _, err := os.Stat("config/config.toml"); err == nil {
			_ = os.Setenv("HEARTDESK_CONFIG_DIR", "config")
		} else if _, err := os.Stat("../../config/config.toml"); err == nil {
			_ = os.Setenv("HEARTDESK_CONFIG_DIR", "../../config")
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
	lines, ok := checkEnv(os.Getenv)
	for _, l := range lines {
		fmt.Println(l)
	}
	if !ok {
		os.Exit(1)
	}
}

// checkEnv は起動に使う環境変数を調べる。HEARTDESK_BASE_DIR だけが必須（サーバーは未設定だと起動しない）。
// HEARTDESK_CONFIG_DIR は未設定なら BASE_DIR/config、HEARTDESK_TENANT_ID は未設定なら default テナントで動くので、
// 未設定は NG にしない。
func checkEnv(getenv func(string) string) (lines []string, ok bool) {
	ok = true
	base := getenv("HEARTDESK_BASE_DIR")
	if base == "" {
		lines = append(lines, "NG: HEARTDESK_BASE_DIR is not set")
		ok = false
	} else {
		lines = append(lines, "OK: HEARTDESK_BASE_DIR="+base)
	}

	if v := getenv("HEARTDESK_CONFIG_DIR"); v != "" {
		lines = append(lines, "OK: HEARTDESK_CONFIG_DIR="+v)
	} else if base != "" {
		lines = append(lines, "OK: HEARTDESK_CONFIG_DIR is not set (using "+filepath.Join(base, "config")+")")
	} else {
		lines = append(lines, "OK: HEARTDESK_CONFIG_DIR is not set (using "+filepath.Join(heartdesk.DefaultRoot, "config")+")")
	}

	if v := getenv("HEARTDESK_TENANT_ID"); v != "" {
		lines = append(lines, "OK: HEARTDESK_TENANT_ID="+v)
	} else {
		lines = append(lines, "OK: HEARTDESK_TENANT_ID is not set (using tenant "+config.DefaultTenantID+")")
	}
	return lines, ok
}

func validateFrontendContracts(wd string) error {
	layoutRaw, err := os.ReadFile(filepath.Join(wd, "web", "templates", "layout.html"))
	if err != nil {
		return err
	}
	layout := string(layoutRaw)
	required := []string{
		`HD_COLLAPSE_KEY = "heartdesk.monitor.collapsed.v1"`,
		`HD_SIDENAV_SERVER_TREE_KEY = "heartdesk.monitor.sidenav.server_tree.v1"`,
		`HD_SIDENAV_ORDER_KEY = "heartdesk.monitor.sidenav.order.v1"`,
	}
	for _, needle := range required {
		if !strings.Contains(layout, needle) {
			return fmt.Errorf("layout.html missing %q", needle)
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
	root := wd
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
		if strings.HasPrefix(path, "bin/") ||
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
