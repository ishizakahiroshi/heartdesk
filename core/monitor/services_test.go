package monitor

import (
	"reflect"
	"testing"
)

func TestNextcloudOCCArgsRunsAsWWWData(t *testing.T) {
	got := nextcloudOCCArgs("maintenance:mode", "--on")
	want := []string{"-n", "-u", "www-data", "/usr/bin/php", "/var/www/nextcloud/occ", "maintenance:mode", "--on"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nextcloudOCCArgs() = %#v, want %#v", got, want)
	}
}
