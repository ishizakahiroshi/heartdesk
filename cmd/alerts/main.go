package main

import (
	"flag"
	"github.com/ishizakahiroshi/heartdesk/alertscli"
)

var testMode = flag.Bool("test", false, "Send test alert mail")

// Keep these small path accessors for the standalone CLI's existing contracts.
func resourceLogPath() string { return alertscli.DefaultPaths().ResourceLog }
func scoreLogPath() string    { return alertscli.DefaultPaths().ScoreLog }
func alertRulesPath() string  { return alertscli.DefaultPaths().Rules }
func lastCheckPath() string   { return alertscli.DefaultPaths().LastCheck }
func lockoutLogPath() string  { return alertscli.DefaultPaths().Lockout }
func sshIPListPath() string   { return alertscli.DefaultPaths().ManagedIPs }

func main() {
	flag.Parse()
	alertscli.New(alertscli.Options{}).Run(*testMode)
}
