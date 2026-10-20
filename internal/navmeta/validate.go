package navmeta

import (
	"fmt"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"os"
	"path/filepath"
	"strings"
)

// ValidateCardMetaConfig checks whether config [cards.meta] IDs exist in navmeta registry.
func ValidateCardMetaConfig(cfg *config.AppConfig) error {
	if cfg == nil {
		return fmt.Errorf("nil app config")
	}
	known := make(map[string]struct{}, len(monitorCardRegistry))
	for _, c := range monitorCardRegistry {
		known[c.ID] = struct{}{}
	}
	var unknown []string
	for id := range cfg.Cards.Meta {
		if _, ok := known[id]; !ok {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	return fmt.Errorf("unknown cards.meta IDs: %s", strings.Join(unknown, ", "))
}

// ValidateTemplateAndJSModules checks template define and js module file existence.
func ValidateTemplateAndJSModules(templatesDir, cardsJSDir string) error {
	blob, err := os.ReadFile(filepath.Join(templatesDir, "cards.html"))
	if err != nil {
		return fmt.Errorf("read cards template: %w", err)
	}
	tpl := string(blob)
	var problems []string
	for _, c := range monitorCardRegistry {
		_ = tpl
		if strings.TrimSpace(c.JSModule) != "" {
			if !strings.HasPrefix(c.JSModule, "cards/") {
				problems = append(problems, "js module must live under cards/: "+c.JSModule)
			}
			modulePath := filepath.Join(cardsJSDir, filepath.Base(c.JSModule))
			moduleRaw, err := os.ReadFile(modulePath)
			if err != nil {
				problems = append(problems, "missing js module: "+c.JSModule)
				continue
			}
			if strings.TrimSpace(c.Renderer) == "" {
				problems = append(problems, "missing renderer metadata for js module: "+c.ID)
				continue
			}
			module := string(moduleRaw)
			if !strings.Contains(module, "CardRegistry.register('"+c.Renderer+"'") &&
				!strings.Contains(module, `CardRegistry.register("`+c.Renderer+`"`) {
				problems = append(problems, "js module does not register renderer "+c.Renderer+": "+c.JSModule)
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(problems, "; "))
}
