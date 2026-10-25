package app

import "testing"

func TestValidateCardConfiguration(t *testing.T) {
	ext := Extensions{Cards: []Card{{Meta: CardMeta{ID: "sec-example", Key: "EXAMPLE", API: "example"}, Screens: []string{"monitor"}}}}
	for _, tc := range []struct {
		name    string
		ids     []string
		aliases map[string]string
		bad     bool
	}{
		{"shared-and-customer", []string{"sec-services", "sec-example"}, nil, false},
		{"legacy", []string{"sec-old"}, map[string]string{"sec-old": "sec-example"}, false},
		{"unknown", []string{"sec-unknown"}, nil, true},
		{"missing-target", nil, map[string]string{"sec-old": "sec-missing"}, true},
		{"cycle", nil, map[string]string{"sec-a": "sec-b", "sec-b": "sec-a"}, true},
		{"replace-shared", nil, map[string]string{"sec-services": "sec-example"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCardConfiguration(ext, tc.ids, tc.aliases)
			if (err != nil) != tc.bad {
				t.Fatalf("error=%v wantFailure=%v", err, tc.bad)
			}
		})
	}
}
