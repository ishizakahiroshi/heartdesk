package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/scheduler"
)

func main() {
	cfg, err := config.LoadSchedulerConfig()
	if err != nil {
		log.Fatalf("scheduler config load failed: %v", err)
	}

	if cfg.BaseDir != "" && os.Getenv("HEARTDESK_BASE_DIR") == "" {
		_ = os.Setenv("HEARTDESK_BASE_DIR", cfg.BaseDir)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	s := scheduler.NewScheduler(cfg, log.Default())
	if err := s.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("scheduler stopped with error: %v", err)
	}
}
