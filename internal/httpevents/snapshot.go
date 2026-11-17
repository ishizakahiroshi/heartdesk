package httpevents

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type IntegrationSnapshot struct {
	GeneratedAt time.Time             `json:"generated_at"`
	Resources   []IntegrationResource `json:"resources"`
}
type IntegrationResource struct {
	Key         string             `json:"key"`
	Source      string             `json:"source"`
	Operation   string             `json:"operation"`
	Status      int                `json:"status"`
	Count       int                `json:"count"`
	First       time.Time          `json:"first"`
	Last        time.Time          `json:"last"`
	LastSuccess time.Time          `json:"last_success,omitempty"`
	Events      []IntegrationEvent `json:"events"`
}
type IntegrationEvent struct {
	ID string    `json:"id"`
	TS time.Time `json:"ts"`
}

func digest(parts ...string) string {
	b, _ := json.Marshal(parts)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Snapshot keeps exact request identities rather than subtracting rolling counts.
// Successful fetches close only the same authenticated scope/operation/resource.
func Snapshot(rows []Row, now time.Time) IntegrationSnapshot {
	resources := map[string]*IntegrationResource{}
	for _, row := range rows {
		r := row.Result
		if r.Operation != "fetch_file" && r.Operation != "preview_file" {
			continue
		}
		if r.Kind != "integration_error" && r.Kind != "success" {
			continue
		}
		ts, err := timestamp(r.Event.TS)
		if err != nil || ts.Before(now.Add(-24*time.Hour)) || ts.After(now.Add(5*time.Minute)) {
			continue
		}
		key := digest(row.Source, r.Operation, r.ResourceHash)
		v := resources[key]
		if v == nil {
			v = &IntegrationResource{Key: key, Source: row.Source, Operation: r.Operation, Status: 404, Events: []IntegrationEvent{}}
			resources[key] = v
		}
		if r.Kind == "success" {
			if ts.After(v.LastSuccess) {
				v.LastSuccess = ts
			}
			continue
		}
		v.Events = append(v.Events, IntegrationEvent{ID: digest(row.Source, r.Event.RequestID), TS: ts})
	}
	out := IntegrationSnapshot{GeneratedAt: now, Resources: []IntegrationResource{}}
	for _, r := range resources {
		active := r.Events[:0]
		for _, e := range r.Events {
			if e.TS.After(r.LastSuccess) {
				active = append(active, e)
			}
		}
		r.Events = active
		sort.Slice(r.Events, func(i, j int) bool {
			if r.Events[i].TS.Equal(r.Events[j].TS) {
				return r.Events[i].ID < r.Events[j].ID
			}
			return r.Events[i].TS.Before(r.Events[j].TS)
		})
		r.Count = len(r.Events)
		if r.Count > 0 {
			r.First = r.Events[0].TS
			r.Last = r.Events[r.Count-1].TS
		}
		out.Resources = append(out.Resources, *r)
	}
	sort.Slice(out.Resources, func(i, j int) bool { return out.Resources[i].Key < out.Resources[j].Key })
	return out
}

func WriteSnapshot(path string, snapshot IntegrationSnapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return &LoadError{Code: "http_snapshot_directory_failed", Fatal: true}
	}
	b, err := json.Marshal(snapshot)
	if err != nil {
		return &LoadError{Code: "http_snapshot_encode_failed", Fatal: true}
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".http-integration-*.tmp")
	if err != nil {
		return &LoadError{Code: "http_snapshot_create_failed", Fatal: true}
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return &LoadError{Code: "http_snapshot_write_failed", Fatal: true}
	}
	if os.Rename(name, path) != nil {
		return &LoadError{Code: "http_snapshot_replace_failed", Fatal: true}
	}
	return nil
}
