package scheduler

import (
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"testing"
	"time"
)

func TestExtractIdentityPreservesHandlerAndSchedule(t *testing.T) {
	oldID := extractJobID
	old, _ := GetJobDef(oldID)
	defer func() {
		registryMu.Lock()
		delete(jobDefs, extractJobID)
		jobDefs[oldID] = old
		extractJobID = oldID
		registryMu.Unlock()
	}()
	if err := ConfigureExtractJobID("example_extract"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.SchedulerConfig{ExtractInterval: 37 * time.Minute, APIRunMap: map[string]string{"example_run": "example_extract"}}
	s := NewScheduler(cfg, nil)
	job, ok := s.jobs["example_extract"]
	if !ok || job.ID != "example_extract" || job.Handler == nil || job.Interval != 37*time.Minute || job.DefaultCronSchedule != old.DefaultCronSchedule {
		t.Fatal("renamed extraction lost behavior")
	}
	if _, ok := s.jobs[oldID]; ok {
		t.Fatal("old extraction ID remains")
	}
	cfg.DisabledJobs = map[string]bool{"example_extract": true}
	s = NewScheduler(cfg, nil)
	if _, ok := s.jobs["example_extract"]; ok {
		t.Fatal("disabled renamed job remains")
	}
}
