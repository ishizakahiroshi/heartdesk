package monitor

import (
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

// No t.Parallel: restore the existing-package execution seam on every exit.
func TestPortAutoUpdateArgumentsWithoutHostExecution(t *testing.T) {
	original := autoUpdateToggler
	t.Cleanup(func() { autoUpdateToggler = original })
	var calls []bool
	autoUpdateToggler = func(enable bool) error { calls = append(calls, enable); return nil }
	h := &Handler{}
	for _, mode := range []string{"enable", "disable"} {
		code, resp := postAction(t, h.actionToggleAutoUpdate, url.Values{"mode": {mode}})
		if code != http.StatusOK || !resp.OK {
			t.Fatalf("mode %q: status=%d ok=%v", mode, code, resp.OK)
		}
	}
	if !reflect.DeepEqual(calls, []bool{true, false}) {
		t.Fatalf("toggle args=%v want [true false]", calls)
	}
	for _, mode := range []string{"", "bogus"} {
		code, resp := postAction(t, h.actionToggleAutoUpdate, url.Values{"mode": {mode}})
		if code != http.StatusBadRequest || resp.OK {
			t.Fatalf("invalid mode %q: status=%d ok=%v", mode, code, resp.OK)
		}
	}
	if len(calls) != 2 {
		t.Fatalf("invalid mode executed toggler: %v", calls)
	}
	autoUpdateToggler = func(enable bool) error { calls = append(calls, enable); return errors.New("synthetic failure") }
	code, resp := postAction(t, h.actionToggleAutoUpdate, url.Values{"mode": {"enable"}})
	if code != http.StatusInternalServerError || resp.OK {
		t.Fatalf("executor failure: status=%d ok=%v", code, resp.OK)
	}
}
