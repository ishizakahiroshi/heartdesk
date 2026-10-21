package ondemand

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// 実システム（apt-get / occ / sudo）は呼ばず、実行器 aptExec を差し替えて、
// 組み立てられるコマンド行と手順の流れを確かめる。

type recordedCmd struct {
	name string
	args []string
}

func (c recordedCmd) line() string { return c.name + " " + strings.Join(c.args, " ") }

// installFakeAptExec は aptExec を差し替える。reply は 1 回の実行に対する出力と終了コードを返す。
func installFakeAptExec(t *testing.T, reply func(c recordedCmd) (string, int)) *[]recordedCmd {
	t.Helper()
	var calls []recordedCmd
	orig := aptExec
	aptExec = func(_ context.Context, w io.Writer, name string, args ...string) int {
		c := recordedCmd{name: name, args: append([]string(nil), args...)}
		calls = append(calls, c)
		out, rc := reply(c)
		_, _ = io.WriteString(w, out)
		return rc
	}
	t.Cleanup(func() { aptExec = orig })
	return &calls
}

func TestOccCommandRunsAsWwwDataViaSudo(t *testing.T) {
	name, args := occCommand("maintenance:mode", "--on")
	want := []string{"-n", "-u", "www-data", "/usr/bin/php", occScriptPath, "maintenance:mode", "--on"}
	if name != "sudo" || !reflect.DeepEqual(args, want) {
		t.Fatalf("occCommand = %s %v, want sudo %v", name, args, want)
	}
}

func TestAptGetCommandUsesSudo(t *testing.T) {
	name, args := aptGetCommand("update")
	want := []string{"-n", "/usr/bin/apt-get", "update"}
	if name != "sudo" || !reflect.DeepEqual(args, want) {
		t.Fatalf("aptGetCommand = %s %v, want sudo %v", name, args, want)
	}
}

func TestRunAptStepsWithOCC(t *testing.T) {
	calls := installFakeAptExec(t, func(recordedCmd) (string, int) { return "", 0 })
	var logBuf bytes.Buffer

	rc, failure := runAptSteps(context.Background(), &logBuf, "full-upgrade", true)
	if rc != 0 || failure != nil {
		t.Fatalf("rc=%d failure=%v, want 0 / nil", rc, failure)
	}
	want := []string{
		"sudo -n -u www-data /usr/bin/php " + occScriptPath + " maintenance:mode --on",
		"sudo -n /usr/bin/apt-get update",
		"sudo -n /usr/bin/apt-get -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef -y full-upgrade",
	}
	var got []string
	for _, c := range *calls {
		got = append(got, c.line())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("実行されたコマンド:\n got  %q\n want %q", got, want)
	}
}

func TestRunAptStepsSkipsOCCWhenNextcloudIsAbsent(t *testing.T) {
	calls := installFakeAptExec(t, func(recordedCmd) (string, int) { return "", 0 })
	var logBuf bytes.Buffer

	rc, failure := runAptSteps(context.Background(), &logBuf, "upgrade", false)
	if rc != 0 || failure != nil {
		t.Fatalf("rc=%d failure=%v, want 0 / nil", rc, failure)
	}
	for _, c := range *calls {
		if strings.Contains(c.line(), "occ") || strings.Contains(c.line(), "maintenance:mode") {
			t.Errorf("occ が無いのに occ の手順を実行した: %s", c.line())
		}
	}
	if len(*calls) != 2 {
		t.Errorf("実行回数 = %d, want 2（apt-get update と upgrade だけ）", len(*calls))
	}
	if !strings.Contains(logBuf.String(), "occ not found") {
		t.Errorf("occ を飛ばしたことがログに 1 行残っていない:\n%s", logBuf.String())
	}
}

func TestRunAptStepsOCCFailureIsLoggedAndStopsBeforeApt(t *testing.T) {
	calls := installFakeAptExec(t, func(c recordedCmd) (string, int) {
		if strings.Contains(c.line(), "maintenance:mode") {
			return "sudo: a password is required\n", 1
		}
		return "", 0
	})
	var logBuf bytes.Buffer

	rc, failure := runAptSteps(context.Background(), &logBuf, "upgrade", true)
	if rc == 0 || failure == nil {
		t.Fatalf("rc=%d failure=%v, want 非 0 / 非 nil", rc, failure)
	}
	if len(*calls) != 1 {
		t.Errorf("occ が失敗したのに続きの手順を実行した: %d 回", len(*calls))
	}
	if !strings.Contains(failure.String(), "a password is required") {
		t.Errorf("失敗の内容（出力の末尾）がエラーに含まれていない: %s", failure.String())
	}
	if !strings.Contains(logBuf.String(), "ERROR: occ maintenance:mode --on failed") ||
		!strings.Contains(logBuf.String(), "a password is required") {
		t.Errorf("失敗の内容がログに残っていない:\n%s", logBuf.String())
	}
}

func TestRunAptStepsAptFailureKeepsTailOfOutput(t *testing.T) {
	long := strings.Repeat("noise line\n", 200) + "E: Could not get lock /var/lib/dpkg/lock-frontend\n"
	installFakeAptExec(t, func(c recordedCmd) (string, int) {
		if strings.Contains(c.line(), "apt-get update") {
			return long, 100
		}
		return "", 0
	})
	var logBuf bytes.Buffer

	rc, failure := runAptSteps(context.Background(), &logBuf, "upgrade", false)
	if rc != 100 || failure == nil {
		t.Fatalf("rc=%d failure=%v, want 100 / 非 nil", rc, failure)
	}
	if !strings.Contains(failure.Tail, "Could not get lock") {
		t.Errorf("出力の末尾が残っていない: %q", failure.Tail)
	}
	if len(failure.Tail) > aptFailureTailBytes {
		t.Errorf("末尾が長すぎる: %d バイト", len(failure.Tail))
	}
	if strings.Contains(failure.Tail, "\n") {
		t.Errorf("末尾に改行が残っている: %q", failure.Tail)
	}
}

func TestOccRunReportsFailure(t *testing.T) {
	installFakeAptExec(t, func(recordedCmd) (string, int) { return "boom", 1 })
	var logBuf bytes.Buffer
	if err := occRun(&logBuf, "maintenance:mode", "--off"); err == nil {
		t.Fatal("occ が失敗したのに nil を返した")
	}
	if !strings.Contains(logBuf.String(), "boom") {
		t.Errorf("失敗の内容がログに残っていない:\n%s", logBuf.String())
	}
}

func TestOccAvailable(t *testing.T) {
	orig := occScriptPath
	t.Cleanup(func() { occScriptPath = orig })

	dir := t.TempDir()
	occScriptPath = filepath.Join(dir, "occ")
	if occAvailable() {
		t.Error("occ が無いのに available と判定した")
	}
	if err := os.WriteFile(occScriptPath, []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !occAvailable() {
		t.Error("occ があるのに available と判定しなかった")
	}
	occScriptPath = dir // ディレクトリは occ ではない
	if occAvailable() {
		t.Error("ディレクトリを occ と判定した")
	}
}
