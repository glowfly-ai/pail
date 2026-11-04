// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const cacheBytes = 16 << 20
const pageBytes = 1 << 20

type cached struct {
	snap Snapshot
	at   time.Time
	size int
}
type cursor struct {
	ID     string `json:"snapshot_id"`
	After  int    `json:"after"`
	Filter string `json:"filter"`
}
type page struct {
	Snapshot
	AsOfMS   int64  `json:"as_of_ms"`
	ServedMS int64  `json:"served_at_ms"`
	AgeMS    int64  `json:"snapshot_age_ms"`
	Total    int    `json:"total"`
	Next     string `json:"next_cursor"`
}
type API struct {
	collector *Collector
	mu        sync.Mutex
	cache     map[string]cached
	order     []string
	bytes     int
	now       func() time.Time
	counter   uint64
	// management: the robot operations projection is configured on this collector
	management bool
}

func NewAPI(c *Collector) *API { return &API{collector: c, cache: map[string]cached{}, now: time.Now} }

// SetManagementProjection tells the capability document whether this collector
// serves the robot operations projection. Called once, before HTTP starts.
func (a *API) SetManagementProjection(on bool) { a.management = on }

func (a *API) Capabilities(w http.ResponseWriter, r *http.Request) {
	if !readRequest(w, r) {
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "UNKNOWN_QUERY", 400)
		return
	}
	if a.collector == nil {
		// "This collector has no observation source" is an answer,
		// not an outage. A 503 here made the page draw the observation tab, retry it
		// every few seconds and paint "the data is old" over a verified timeline. The
		// data endpoints keep their 503; the capabilities say what exists.
		write(w, r, map[string]any{"schema_version": 1, "document_kind": "ObservationCapabilities",
			"observation": false, "endpoints": []string{}, "management_projection": a.management,
			"reason": "SOURCE_MAP_UNCONFIGURED"})
		return
	}
	c := a.collector.config
	doc := map[string]any{"schema_version": 1, "document_kind": "ObservationCapabilities", "source_id": c.SourceID, "collector_instance_id": a.collector.instance, "deployment_id": c.DeploymentID, "deployment_known": c.DeploymentID != "", "facets": a.collector.facetKinds(), "endpoints": []string{"/v2/observation/robots"}, "limits": map[string]int{"registered": MaxRobots, "unresolved": MaxUnresolved, "page_rows": 1000, "page_bytes": pageBytes, "snapshots": 8, "snapshot_bytes": cacheBytes, "snapshot_ttl_seconds": 30}, "scope": "configured_collector_sources"}
	if a.collector.HasLedgerSource() {
		// what the status page may draw: the decision history of the verified
		// ledger, and whether signed events reach this collector at all
		doc["endpoints"] = []string{"/v2/observation/robots", DecisionsEndpoint}
		doc["feeds"] = map[string]bool{"ledger_decisions": true, "signed_events": a.collector.signedFeed()}
		// what the page may draw (design 8.3). A tab or a column without a
		// source behind it is not drawn; these say which have one.
		doc["observation"] = true
		doc["signed_events"] = a.collector.declares("legacy_burst")
		doc["signed_permit_statements"] = a.collector.declares("legacy_permit")
		doc["management_projection"] = a.management
		doc["management_observation"] = a.collector.allows("management")
		doc["clock_binding"] = a.collector.clockBinding()
	}
	write(w, r, doc)
}
func readRequest(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "METHOD_NOT_ALLOWED", 405)
		return false
	}
	return true
}
func write(w http.ResponseWriter, r *http.Request, v any) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "HEAD" {
		json.NewEncoder(w).Encode(v)
	}
}
func (a *API) Robots(w http.ResponseWriter, r *http.Request) {
	if !readRequest(w, r) {
		return
	}
	if a.collector == nil {
		http.Error(w, "SOURCE_MAP_UNCONFIGURED", 503)
		return
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		http.Error(w, "INVALID_QUERY", 400)
		return
	}
	limit := 200
	for k, v := range q {
		if len(v) != 1 || len(v[0]) > 2048 {
			http.Error(w, "INVALID_QUERY", 400)
			return
		}
		switch k {
		case "limit":
			limit, e = strconv.Atoi(v[0])
			if e != nil || limit < 1 || limit > 1000 {
				http.Error(w, "INVALID_LIMIT", 400)
				return
			}
		case "robot_id", "deployment_id", "source_id", "cursor":
		default:
			http.Error(w, "UNKNOWN_QUERY", 400)
			return
		}
	}
	filters := url.Values{}
	for _, k := range []string{"robot_id", "deployment_id", "source_id"} {
		if q.Has(k) {
			filters[k] = q[k]
		}
	}
	filter := filters.Encode()
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for len(a.order) > 0 {
		v := a.cache[a.order[0]]
		if now.Sub(v.at) < 30*time.Second {
			break
		}
		a.bytes -= v.size
		delete(a.cache, a.order[0])
		a.order = a.order[1:]
	}
	var v cached
	cur := cursor{Filter: filter}
	if q.Get("cursor") != "" {
		b, err := base64.RawURLEncoding.DecodeString(q.Get("cursor"))
		if err != nil || StrictJSON(b, &cur) != nil || cur.ID == "" || cur.After < 0 {
			http.Error(w, "INVALID_CURSOR", 400)
			return
		}
		if cur.Filter != filter {
			http.Error(w, "FILTER_CHANGED", 400)
			return
		}
		var ok bool
		v, ok = a.cache[cur.ID]
		if !ok {
			http.Error(w, "SNAPSHOT_EXPIRED", 409)
			return
		}
	} else {
		s := a.collector.Snapshot()
		selected := []Robot{}
		for _, row := range s.Robots {
			if (q.Has("source_id") && q.Get("source_id") != s.SourceID) || (q.Has("robot_id") && q.Get("robot_id") != row.Key.RobotID) || (q.Has("deployment_id") && q.Get("deployment_id") != row.Key.DeploymentID) {
				continue
			}
			selected = append(selected, row)
		}
		s.Robots = selected
		if len(filters) > 0 {
			s.Unresolved = []Unresolved{}
		}
		tagInput := s.Instance + ":" + s.Revision + ":" + filter + ":" + strconv.Itoa(limit)
		sum := sha256.Sum256([]byte(tagInput))
		etag := `"` + hex.EncodeToString(sum[:]) + `"`
		w.Header().Set("ETag", etag)
		w.Header().Set("X-Snapshot-Revision", s.Revision)
		// Snapshot computes all TTL transitions BEFORE conditional response handling.
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(304)
			return
		}
		b, _ := json.Marshal(s)
		if len(b) > cacheBytes {
			http.Error(w, "SNAPSHOT_OVERSIZE", 503)
			return
		}
		for len(a.order) >= 8 || a.bytes+len(b) > cacheBytes {
			old := a.order[0]
			a.bytes -= a.cache[old].size
			delete(a.cache, old)
			a.order = a.order[1:]
		}
		a.counter++
		cur.ID = s.Instance + ":" + strconv.FormatUint(a.counter, 10)
		v = cached{s, now, len(b)}
		a.cache[cur.ID] = v
		a.order = append(a.order, cur.ID)
		a.bytes += len(b)
	}
	if cur.After > len(v.snap.Robots) {
		http.Error(w, "INVALID_CURSOR", 400)
		return
	}
	// Copy cached data before age downgrade. Old pages retain their as-of marker,
	// but never present a cached FRESH verdict as a newly observed fact.
	b, _ := json.Marshal(v.snap)
	var s Snapshot
	json.Unmarshal(b, &s)
	elapsed := now.Sub(v.at)
	if elapsed < 0 {
		http.Error(w, "CLOCK_UNCERTAIN", 503)
		return
	}
	for i := range s.Robots {
		for j := range s.Robots[i].Sources {
			for k, f := range s.Robots[i].Sources[j].Facets {
				if f.AgeMS != nil {
					age := *f.AgeMS + elapsed.Milliseconds()
					f.AgeMS = &age
					if f.FreshnessBasis == LedgerBasis {
						// a state ages with its verification, not with a record
						if age >= LedgerFreshness.Milliseconds() {
							f.ReceiptQuality = "STALE"
							if f.Quality == "FRESH" || (f.Quality == "STALE" && f.Reason == "INDEX_BEHIND") {
								f.Quality = "STALE"
								f.Reason = "VERIFICATION_OLD"
							}
						}
					} else if age >= ttls[k].Milliseconds() {
						f.ReceiptQuality = "STALE"
						if f.Quality == "FRESH" || f.Quality == "UNKNOWN" {
							f.Quality = "STALE"
							f.Reason = "TTL_EXPIRED"
						}
						f.Active = nil
					}
				}
				s.Robots[i].Sources[j].Facets[k] = f
			}
		}
		if old := s.Robots[i].Summary; old != nil {
			// judged again on the aged facets; the wait of row 10 is not extended
			s.Robots[i].Summary = summarize(s.Robots[i], old.Inputs.Wait)
		}
	}
	total := len(s.Robots)
	all := s.Robots
	s.Robots = []Robot{}
	resp := page{Snapshot: s, AsOfMS: s.GeneratedMS, ServedMS: now.UnixMilli(), AgeMS: elapsed.Milliseconds(), Total: total}
	end := cur.After
	for end < total && end-cur.After < limit {
		resp.Robots = append(resp.Robots, all[end])
		b, _ = json.Marshal(resp)
		if len(b) > pageBytes-2048 {
			resp.Robots = resp.Robots[:len(resp.Robots)-1]
			break
		}
		end++
	}
	if end == cur.After && end < total {
		http.Error(w, "ROBOT_ROW_OVERSIZE", 503)
		return
	}
	if end < total {
		cur.After = end
		b, _ = json.Marshal(cur)
		resp.Next = base64.RawURLEncoding.EncodeToString(b)
	}
	b, _ = json.Marshal(resp)
	if len(b) > pageBytes {
		http.Error(w, "PAGE_OVERSIZE", 503)
		return
	}
	w.Header().Set("X-Snapshot-Revision", resp.Revision)
	write(w, r, resp)
}
func (a *API) String() string { return fmt.Sprintf("observation API (bounded cache)") }
