// Package events keeps a small ring of notable network happenings — WAN
// session changes, WARP tunnel drops and recoveries, router reboots and
// bufferbloat probe results — so the Overview can show a "what happened"
// feed instead of making the user reconstruct the timeline from charts.
// The ring persists to disk so events survive monitor restarts.
package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/log"
)

// Event is one notable occurrence.
type Event struct {
	At    int64  `json:"at"`   // unix seconds
	Kind  string `json:"kind"` // wan | warp | reboot | probe | bloat | conntrack | config | monitor | wifi | orbi | satellite
	Sev   string `json:"sev"`  // ok | warn | crit | info
	Msg   string `json:"msg"`
	Count int    `json:"count,omitempty"` // collapsed repeats: 27 restarts, N flaps
}

// ringCap is generous on purpose: 1000 entries is still ~100 KB on disk, and
// the feed must hold a week of WARP flaps and probe surprises without the
// early history being pushed out.
const ringCap = 1000

// Store is a persistent, newest-first event ring.
type Store struct {
	mu     sync.Mutex
	events []Event
	path   string
	hook   func(kind, sev, msg string)
}

// SetHook registers a callback run (outside the store lock) for every
// event added, e.g. to push alerts. Call before events start flowing.
func (s *Store) SetHook(fn func(kind, sev, msg string)) {
	s.mu.Lock()
	s.hook = fn
	s.mu.Unlock()
}

// New loads any persisted events and returns the store. The loaded ring is
// compacted, so a history of repeated events (a stack of restarts from many
// deploys, say) heals into single counted entries.
func New(path string) *Store {
	s := &Store{path: path}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &s.events); err != nil {
			// A corrupt file must not silently look like an empty store
			// that then overwrites the history on first persist.
			log.Logger.Warn().Err(err).Str("file", path).Msg("corrupt event history, starting fresh")
		} else {
			s.events = collapse(s.events)
		}
	}
	return s
}

// Add appends an event (newest first), collapses repeats and persists the
// ring. Two collapses keep the feed readable: a restart marker always merges
// into a leading run of restart markers (deploys during development would
// otherwise bury the feed), and an identical message within ten minutes
// becomes a counted flap instead of a wall of entries.
func (s *Store) Add(kind, sev, msg string) {
	s.mu.Lock()
	s.addLocked(kind, sev, msg)
	hook := s.hook
	s.mu.Unlock()
	if hook != nil {
		hook(kind, sev, msg)
	}
}

func (s *Store) addLocked(kind, sev, msg string) {
	ev := Event{At: time.Now().Unix(), Kind: kind, Sev: sev, Msg: msg, Count: 1}
	if len(s.events) > 0 {
		last := s.events[0]
		lastCount := last.Count
		if lastCount < 1 {
			lastCount = 1 // entries written before counting existed
		}
		if kind == "monitor" && last.Kind == "monitor" {
			ev.Count = lastCount + 1
		} else if last.Kind == kind && last.Sev == sev && last.Msg == msg && ev.At-last.At < 600 {
			ev.Count = lastCount + 1
		}
	}
	if ev.Count > 1 {
		s.events = s.events[1:] // the merged entry is superseded
	}
	s.events = append([]Event{ev}, s.events...)
	if len(s.events) > ringCap {
		s.events = s.events[:ringCap]
	}
	s.persistLocked()
}

// collapse merges consecutive runs of the same event (monitor restarts,
// identical flaps within ten minutes) into counted entries. Input and output
// are newest-first.
//
// The merged entry mirrors what addLocked builds at runtime: it keeps the
// newest occurrence's At/Sev/Msg and sums the counts. The ten-minute flap
// window is measured between adjacent occurrences (as addLocked compares each
// new event to the previous one), so a run reloads exactly as it was built.
func collapse(events []Event) []Event {
	var out []Event
	var runOldest int64 // At of the oldest occurrence merged into out's last entry
	for _, ev := range events {
		if ev.Count < 1 {
			ev.Count = 1 // entries written before counting existed
		}
		if len(out) > 0 {
			last := &out[len(out)-1]
			same := last.Kind == ev.Kind &&
				(ev.Kind == "monitor" ||
					(last.Sev == ev.Sev && last.Msg == ev.Msg && runOldest-ev.At < 600))
			if same {
				last.Count += ev.Count
				runOldest = ev.At
				continue
			}
		}
		out = append(out, ev)
		runOldest = ev.At
	}
	return out
}

func (s *Store) persistLocked() {
	if s.path == "" {
		return
	}
	if b, err := json.Marshal(s.events); err == nil {
		_ = os.MkdirAll(filepath.Dir(s.path), 0o755)
		tmp := s.path + ".tmp"
		if os.WriteFile(tmp, b, 0o644) == nil {
			_ = os.Rename(tmp, s.path)
		}
	}
}

// List returns up to n most recent events.
func (s *Store) List(n int) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > len(s.events) {
		n = len(s.events)
	}
	if n < 0 {
		n = 0
	}
	out := make([]Event, n)
	copy(out, s.events[:n])
	return out
}

// CountSince counts occurrences of one kind newer than the given unix
// second, weighting collapsed repeats by their Count. Used for "N reconnects
// in the last 24 h / 7 d" style figures.
func (s *Store) CountSince(kind string, since int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, ev := range s.events {
		if ev.Kind == kind && ev.At >= since {
			c := ev.Count
			if c < 1 {
				c = 1
			}
			n += c
		}
	}
	return n
}
