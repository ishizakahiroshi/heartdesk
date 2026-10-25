package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ishizakahiroshi/heartdesk/app"
)

func main() {
	opts := app.OptionsFromEnvironment()
	opts.SchedulerOnly = true
	runtime, err := app.New(opts)
	if err != nil {
		log.Fatal(err)
	}
	defer runtime.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := runtime.RunScheduler(ctx); err != nil {
		log.Fatal(err)
	}
}
