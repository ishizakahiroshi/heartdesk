package monitor

import (
	"bytes"
	"encoding/json"
)

// collectorObject rejects failure envelopes before decoding into a success
// struct. json.Unmarshal otherwise ignores _error and produces zero values.
// Check field presence as well: {} is not evidence of a successful collection.
func collectorObject(raw json.RawMessage, required ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return false
	}
	if _, failed := fields["_error"]; failed {
		return false
	}
	for _, key := range required {
		value, ok := fields[key]
		if !ok || len(value) == 0 {
			return false
		}
		if key != "order" && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}
