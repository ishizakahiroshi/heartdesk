package command

import (
	"context"
	"os/exec"
	"time"
)

type Spec struct {
	Name    string
	Command string
	Args    []string
	Timeout time.Duration
}

type Runner interface {
	Run(ctx context.Context, spec Spec) (string, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, spec Spec) (string, error) {
	if spec.Timeout <= 0 {
		spec.Timeout = 10 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, spec.Command, spec.Args...).CombinedOutput()
	return string(out), err
}
