package alertscli

import (
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

// Paths names every independent input/output used by the compatibility CLI.
// An empty member uses the standalone heartdesk default, resolved by New.
type Paths struct {
	ResourceLog, ScoreLog, Rules, State, LastCheck, ManagedIPs, Lockout string
}

// Dependencies replaces external effects per Runner. Nil members use the
// standalone implementation. Tests can replace all effects without process-wide
// hooks, real filesystem paths, system commands, or notification delivery.
type Dependencies struct {
	Now            func() time.Time
	Open           func(string) (io.ReadCloser, error)
	ReadFile       func(string) ([]byte, error)
	MkdirAll       func(string, os.FileMode) error
	WriteFile      func(string, []byte, os.FileMode) error
	Command        func(...string) string
	SendMail       func(map[string]string, string, string, string) error
	Stdout, Stderr io.Writer
}

// Options preserves standalone behavior unless the caller explicitly supplies
// paths, test-message identity, or external-effect dependencies.
type Options struct {
	Paths                 Paths
	TestSubject, TestBody string
	Dependencies          Dependencies
}

// Runner performs one historical CLI evaluation cycle. Separate runners own
// separate options/dependencies. Calls on one runner must be serialized, as its
// configured state file and dependency callbacks may be shared.
type Runner struct {
	paths                 Paths
	testSubject, testBody string
	deps                  Dependencies
}

// DefaultPaths resolves the public CLI's existing environment-based defaults.
// The compatibility state file intentionally remains separate from scheduler state.
func DefaultPaths() Paths {
	return Paths{
		ResourceLog: heartdesk.PathOrDefault("data/csv/resource_log.csv"),
		ScoreLog:    heartdesk.PathOrDefault("data/csv/threat_score.csv"),
		Rules:       heartdesk.PathOrDefault("data/json/alert_rules.json"),
		State:       "/tmp/heartdesk_alert_state.json",
		LastCheck:   heartdesk.PathOrDefault("data/json/alert_check_last.csv"),
		ManagedIPs:  filepath.Join(heartdesk.ConfigDir(), "managed_ips.toml"),
		Lockout:     heartdesk.PathOrDefault("data/nc_extract/lockout_events.jsonl"),
	}
}

// New copies the options and fills only omitted fields. Construction performs
// no filesystem reads/writes, command execution, or notification delivery.
func New(options Options) *Runner {
	paths := options.Paths
	defaults := DefaultPaths()
	targets := []*string{&paths.ResourceLog, &paths.ScoreLog, &paths.Rules, &paths.State, &paths.LastCheck, &paths.ManagedIPs, &paths.Lockout}
	values := []string{defaults.ResourceLog, defaults.ScoreLog, defaults.Rules, defaults.State, defaults.LastCheck, defaults.ManagedIPs, defaults.Lockout}
	for i := range targets {
		if *targets[i] == "" {
			*targets[i] = values[i]
		}
	}
	deps := options.Dependencies
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Open == nil {
		deps.Open = func(path string) (io.ReadCloser, error) { return os.Open(path) }
	}
	if deps.ReadFile == nil {
		deps.ReadFile = os.ReadFile
	}
	if deps.MkdirAll == nil {
		deps.MkdirAll = os.MkdirAll
	}
	if deps.WriteFile == nil {
		deps.WriteFile = os.WriteFile
	}
	if deps.Command == nil {
		deps.Command = defaultCommand
	}
	if deps.SendMail == nil {
		deps.SendMail = sendMail
	}
	if deps.Stdout == nil {
		deps.Stdout = os.Stdout
	}
	if deps.Stderr == nil {
		deps.Stderr = os.Stderr
	}
	subject, body := options.TestSubject, options.TestBody
	if subject == "" {
		subject = "【テスト】heartdesk アラート通知テスト"
	}
	if body == "" {
		body = "このメールはアラート通知テストです。\n\nシステムは正常に機能しています。"
	}
	return &Runner{paths: paths, testSubject: subject, testBody: body, deps: deps}
}
