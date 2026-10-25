package authz

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

// SetUserDenyActions は actions_user.toml の [users.<username>] の deny リストを置き換える。
// deny が空配列/空文字のみの場合、そのユーザーのエントリは削除される。
// username が空、もしくは無効な場合は何もしない。
func SetUserDenyActions(username string, deny []string) error {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" {
		return nil
	}

	userWriteMu.Lock()
	defer userWriteMu.Unlock()

	path := filepath.Join(configDir(), "actions_user.toml")
	doc, err := loadActionsUserForWrite(path)
	if err != nil {
		return err
	}

	normalized := normalizeDenyList(deny)
	if doc.Users == nil {
		doc.Users = map[string]ActionsUserEntry{}
	}
	if len(normalized) == 0 {
		delete(doc.Users, key)
	} else {
		doc.Users[key] = ActionsUserEntry{Deny: normalized}
	}

	if err := writeTOML(path, actionsUserSortedView(doc)); err != nil {
		return err
	}
	ResetActionsCache()
	return nil
}

// SetUserHideCards は cards_user.toml の [users.<username>] の hide_cards / hide_child_cards を置き換える。
// 全て空の場合はユーザーエントリを削除する。
func SetUserHideCards(username string, hideCards []string, hideChildCards map[string][]string) error {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" {
		return nil
	}

	userWriteMu.Lock()
	defer userWriteMu.Unlock()

	path := filepath.Join(configDir(), "cards_user.toml")
	doc, err := loadCardsUserForWrite(path)
	if err != nil {
		return err
	}

	normalizedCards := normalizeIDList(hideCards)
	normalizedChild := normalizeHideChild(hideChildCards)

	if doc.Users == nil {
		doc.Users = map[string]CardsUserEntry{}
	}
	if len(normalizedCards) == 0 && len(normalizedChild) == 0 {
		delete(doc.Users, key)
	} else {
		doc.Users[key] = CardsUserEntry{
			HideCards:      normalizedCards,
			HideChildCards: normalizedChild,
		}
	}

	if err := writeTOML(path, cardsUserSortedView(doc)); err != nil {
		return err
	}
	ResetCardsCache()
	return nil
}

// DeleteUserEntries は username に対応する user 層の全エントリを削除する。
// users.toml からユーザー削除時に併せて呼び出す用途。
func DeleteUserEntries(username string) error {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" {
		return nil
	}

	userWriteMu.Lock()
	defer userWriteMu.Unlock()

	actionsPath := filepath.Join(configDir(), "actions_user.toml")
	if actionsDoc, err := loadActionsUserForWrite(actionsPath); err == nil {
		if _, ok := actionsDoc.Users[key]; ok {
			delete(actionsDoc.Users, key)
			if err := writeTOML(actionsPath, actionsUserSortedView(actionsDoc)); err != nil {
				return err
			}
			ResetActionsCache()
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	cardsPath := filepath.Join(configDir(), "cards_user.toml")
	if cardsDoc, err := loadCardsUserForWrite(cardsPath); err == nil {
		if _, ok := cardsDoc.Users[key]; ok {
			delete(cardsDoc.Users, key)
			if err := writeTOML(cardsPath, cardsUserSortedView(cardsDoc)); err != nil {
				return err
			}
			ResetCardsCache()
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	return nil
}

var userWriteMu sync.Mutex

func loadActionsUserForWrite(path string) (ActionsUserFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ActionsUserFile{Users: map[string]ActionsUserEntry{}}, nil
		}
		return ActionsUserFile{}, err
	}
	var doc ActionsUserFile
	if _, err := toml.Decode(string(raw), &doc); err != nil {
		return ActionsUserFile{}, err
	}
	if doc.Users == nil {
		doc.Users = map[string]ActionsUserEntry{}
	}
	return doc, nil
}

func loadCardsUserForWrite(path string) (CardsUserFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return CardsUserFile{Users: map[string]CardsUserEntry{}}, nil
		}
		return CardsUserFile{}, err
	}
	var doc CardsUserFile
	if _, err := toml.Decode(string(raw), &doc); err != nil {
		return CardsUserFile{}, err
	}
	if doc.Users == nil {
		doc.Users = map[string]CardsUserEntry{}
	}
	return doc, nil
}

// actionsUserSortedView / cardsUserSortedView はエンコード時のキー順を安定化するためのラッパ。
// TOML エンコーダのマップは安定順で出力されるが、ラッパで明示的に構造化する。
type actionsUserSorted struct {
	Users map[string]ActionsUserEntry `toml:"users"`
}

type cardsUserSorted struct {
	Users map[string]CardsUserEntry `toml:"users"`
}

func actionsUserSortedView(doc ActionsUserFile) actionsUserSorted {
	return actionsUserSorted{Users: doc.Users}
}

func cardsUserSortedView(doc CardsUserFile) cardsUserSorted {
	return cardsUserSorted{Users: doc.Users}
}

func writeTOML(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var buf strings.Builder
	enc := toml.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return err
	}
	data := []byte(buf.String())
	if len(data) == 0 || data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func normalizeDenyList(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(src))
	out := make([]string, 0, len(src))
	for _, raw := range src {
		key := normalizeActionKey(raw)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeIDList(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(src))
	out := make([]string, 0, len(src))
	for _, raw := range src {
		key := CanonicalCardID(raw)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeHideChild(src map[string][]string) map[string][]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string][]string, len(src))
	for parentID, children := range src {
		parent := CanonicalCardID(parentID)
		if parent == "" {
			continue
		}
		ids := normalizeIDList(children)
		if len(ids) == 0 {
			continue
		}
		out[parent] = normalizeIDList(append(out[parent], ids...))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
