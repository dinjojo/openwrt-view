// Package usage persists per-client byte counters so daily per-device
// usage survives restarts and nlbwmon period roll-overs.
//
// Every snapshot appends one JSON line per client to
// <dir>/usage-YYYY-MM-DD.jsonl (calendar day in the store's zone — see
// SetLocation; the same zone as the report's days):
//
//	{"t":1792651500,"mac":"AA:BB:CC:DD:EE:FF","rx":123456,"tx":7890}
//
// rx/tx are the cumulative counters as reported by the client store
// (nlbwmon's per-period totals). Daily usage is the sum of consecutive
// increases between snapshots attributed to the day of the later
// snapshot — which equals last − first within a day, plus the gap from the
// previous day's last snapshot to the first one of the day. A counter that
// went backwards (nlbwmon period reset, restart) contributes 0 for that
// step.
package usage

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Sample is one persisted counter reading.
type Sample struct {
	T   int64  `json:"t"`
	MAC string `json:"mac"`
	Rx  int64  `json:"rx"`
	Tx  int64  `json:"tx"`
}

// ClientDay is one device's usage on one day.
type ClientDay struct {
	RxGB float64 `json:"rx_gb"`
	TxGB float64 `json:"tx_gb"`
}

// Day is one calendar day of per-client usage.
type Day struct {
	Date    string               `json:"date"` // YYYY-MM-DD, local time
	Clients map[string]ClientDay `json:"clients"`
}

// keepDays is how long usage files are kept (queries go back 400 days —
// the Data Usage card's monthly chart — plus the baseline day).
const keepDays = 401

// Store reads and writes the usage files in one directory.
type Store struct {
	dir string
	mu  sync.Mutex
	loc *time.Location // calendar-day zone for file names; nil = the time's own zone
}

// New returns a store rooted at dir (created on first write).
func New(dir string) *Store { return &Store{dir: dir} }

// SetLocation sets the zone whose calendar days name the usage files and
// bound Daily's days — the same zone /api/report uses (the -tz flag), so a
// usage day and a report day cover the same 24 hours. Without it the zone
// of the time passed in is used. Files written before the zone changed
// keep their old (e.g. UTC) day boundaries. Call before use.
func (s *Store) SetLocation(loc *time.Location) { s.loc = loc }

// local converts t into the store's day zone.
func (s *Store) local(t time.Time) time.Time {
	if s.loc != nil {
		return t.In(s.loc)
	}
	return t
}

// Dir is the directory the files live in.
func (s *Store) Dir() string { return s.dir }

func fileName(day time.Time) string { return "usage-" + day.Format("2006-01-02") + ".jsonl" }

// Append writes one snapshot (all samples share t) to the file of t's day
// and prunes files older than keepDays.
func (s *Store) Append(t time.Time, samples []Sample) error {
	if len(samples) == 0 {
		return nil
	}
	t = s.local(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	var b strings.Builder
	for _, sm := range samples {
		sm.T = t.Unix()
		sm.MAC = strings.ToUpper(sm.MAC)
		line, err := json.Marshal(sm)
		if err != nil {
			continue
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	f, err := os.OpenFile(filepath.Join(s.dir, fileName(t)), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	s.pruneLocked(t)
	return nil
}

func (s *Store) pruneLocked(now time.Time) {
	cutoff := dayStart(now).AddDate(0, 0, -keepDays).Format("2006-01-02")
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "usage-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		if date := strings.TrimSuffix(strings.TrimPrefix(name, "usage-"), ".jsonl"); len(date) == 10 && date < cutoff {
			_ = os.Remove(filepath.Join(s.dir, name))
		}
	}
}

// Daily returns per-day per-client usage for the last n calendar days
// ending with now's day (today partial), oldest first. Days without a file
// are absent. The day before the window is read (when present) only as the
// baseline for the first day.
func (s *Store) Daily(n int, now time.Time) []Day {
	s.mu.Lock()
	defer s.mu.Unlock()
	today := dayStart(s.local(now))
	type last struct{ rx, tx int64 }
	prev := map[string]last{}
	// Baseline from the day before the window.
	for _, sm := range readFile(filepath.Join(s.dir, fileName(today.AddDate(0, 0, -n)))) {
		prev[sm.MAC] = last{sm.Rx, sm.Tx}
	}
	out := []Day{}
	for i := n - 1; i >= 0; i-- {
		day := today.AddDate(0, 0, -i)
		samples := readFile(filepath.Join(s.dir, fileName(day)))
		if samples == nil {
			continue
		}
		type tot struct{ rx, tx int64 }
		totals := map[string]*tot{}
		for _, sm := range samples {
			t := totals[sm.MAC]
			if t == nil {
				t = &tot{}
				totals[sm.MAC] = t
			}
			if p, ok := prev[sm.MAC]; ok {
				if d := sm.Rx - p.rx; d > 0 {
					t.rx += d
				}
				if d := sm.Tx - p.tx; d > 0 {
					t.tx += d
				}
			}
			prev[sm.MAC] = last{sm.Rx, sm.Tx}
		}
		d := Day{Date: day.Format("2006-01-02"), Clients: map[string]ClientDay{}}
		for mac, t := range totals {
			d.Clients[mac] = ClientDay{RxGB: gb(t.rx), TxGB: gb(t.tx)}
		}
		out = append(out, d)
	}
	return out
}

// readFile returns a file's samples in time order; nil when the file is
// missing. Malformed lines (e.g. a torn final write) are skipped.
func readFile(path string) []Sample {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	res := []Sample{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var sm Sample
		if json.Unmarshal(sc.Bytes(), &sm) != nil || sm.MAC == "" {
			continue
		}
		sm.MAC = strings.ToUpper(sm.MAC)
		res = append(res, sm)
	}
	sort.SliceStable(res, func(i, j int) bool { return res[i].T < res[j].T })
	return res
}

// gb converts bytes to decimal gigabytes rounded to 0.001 GB (1 MB) so
// light devices do not all collapse to 0.
func gb(b int64) float64 { return math.Round(float64(b)/1e6) / 1000 }

func dayStart(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}
