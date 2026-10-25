package filelock

import (
	"errors"
	publiclock "github.com/ishizakahiroshi/heartpost/filelock"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPublicAndInternalLockShareContentionAndRelease(t *testing.T) {
	if ErrLocked != publiclock.ErrLocked {
		t.Fatal("lock sentinels differ")
	}
	path := filepath.Join(t.TempDir(), "example.lock")
	release, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if next, err := publiclock.TryAcquire(path); !errors.Is(err, ErrLocked) {
		if next != nil {
			next()
		}
		release()
		t.Fatal("public path bypassed internal lock", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPublicLockContentionChild$")
	cmd.Env = append(os.Environ(), "HEARTDESK_TEST_PUBLIC_LOCK_PATH="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		release()
		t.Fatalf("cross-process lock failed: %v\n%s", err, out)
	}
	release()
	next, err := publiclock.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	next()
	if next, err := Acquire(filepath.Join(t.TempDir(), "missing", "example.lock")); err == nil || errors.Is(err, ErrLocked) {
		if next != nil {
			next()
		}
		t.Fatal("I/O failure misclassified as contention", err)
	}
}

func TestPublicLockContentionChild(t *testing.T) {
	path := os.Getenv("HEARTDESK_TEST_PUBLIC_LOCK_PATH")
	if path == "" {
		t.Skip("child")
	}
	release, err := publiclock.Acquire(path)
	if release != nil {
		release()
	}
	if !errors.Is(err, publiclock.ErrLocked) {
		t.Fatal("held lock acquired by child", err)
	}
}
