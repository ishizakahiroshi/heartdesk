package monitor

import "testing"

func TestNcDetectUserCreatedEvents(t *testing.T) {
	records := []ncLogRecord{
		{Time: "2026-08-31T09:00:00+09:00", Message: `User created: "alice"`},
		{Time: "2026-08-31T09:00:01+09:00", Message: `Login successful: "someone_else"`},
		{Time: "2026-08-31T09:05:00+09:00", Message: `User created: "sato"`},
	}

	got := ncDetectUserCreatedEvents(records)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2: %+v", len(got), got)
	}
	if got[0].UID != "alice" || got[0].Time != "2026-08-31T09:00:00+09:00" {
		t.Fatalf("got[0] = %+v", got[0])
	}
	if got[1].UID != "sato" || got[1].Time != "2026-08-31T09:05:00+09:00" {
		t.Fatalf("got[1] = %+v", got[1])
	}
}

func TestNcDetectFirstLogins(t *testing.T) {
	cases := []struct {
		name     string
		created  []NCUserCreatedEvent
		logins   []ncLogRecord
		wantUIDs []string
	}{
		{
			name:    "matches first login after creation",
			created: []NCUserCreatedEvent{{Time: "2026-08-31T09:00:00+09:00", UID: "alice"}},
			logins: []ncLogRecord{
				{Time: "2026-08-31T09:01:00+09:00", User: "alice", Message: `Login successful: "alice"`},
			},
			wantUIDs: []string{"alice"},
		},
		{
			name:    "second login for same uid is not reported",
			created: []NCUserCreatedEvent{{Time: "2026-08-31T09:00:00+09:00", UID: "alice"}},
			logins: []ncLogRecord{
				{Time: "2026-08-31T09:01:00+09:00", User: "alice", Message: `Login successful: "alice"`},
				{Time: "2026-08-31T10:00:00+09:00", User: "alice", Message: `Login successful: "alice"`},
			},
			wantUIDs: []string{"alice"},
		},
		{
			name:    "login for uid never created is ignored",
			created: []NCUserCreatedEvent{{Time: "2026-08-31T09:00:00+09:00", UID: "alice"}},
			logins: []ncLogRecord{
				{Time: "2026-08-31T09:01:00+09:00", User: "existing_user", Message: `Login successful: "existing_user"`},
			},
			wantUIDs: nil,
		},
		{
			name:    "failed login is ignored",
			created: []NCUserCreatedEvent{{Time: "2026-08-31T09:00:00+09:00", UID: "alice"}},
			logins: []ncLogRecord{
				{Time: "2026-08-31T09:01:00+09:00", User: "alice", Message: `Login failed: "alice"`},
			},
			wantUIDs: nil,
		},
		{
			name:    "success before creation time is ignored",
			created: []NCUserCreatedEvent{{Time: "2026-08-31T09:00:00+09:00", UID: "alice"}},
			logins: []ncLogRecord{
				{Time: "2026-08-31T08:59:00+09:00", User: "alice", Message: `Login successful: "alice"`},
			},
			wantUIDs: nil,
		},
		{
			name:    "user extracted from message when User field is empty",
			created: []NCUserCreatedEvent{{Time: "2026-08-31T09:00:00+09:00", UID: "alice"}},
			logins: []ncLogRecord{
				{Time: "2026-08-31T09:01:00+09:00", User: "", Message: `Login successful: "alice"`},
			},
			wantUIDs: []string{"alice"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ncDetectFirstLogins(tc.created, tc.logins)
			if len(got) != len(tc.wantUIDs) {
				t.Fatalf("len(got) = %d, want %d: %+v", len(got), len(tc.wantUIDs), got)
			}
			for i, uid := range tc.wantUIDs {
				if got[i].UID != uid {
					t.Fatalf("got[%d].UID = %q, want %q", i, got[i].UID, uid)
				}
			}
		})
	}
}
