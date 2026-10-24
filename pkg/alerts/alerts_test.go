package alerts

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewParsesTopic(t *testing.T) {
	cases := []struct {
		url, endpoint, topic string
		wantErr              bool
	}{
		{"https://ntfy.sh/mytopic", "https://ntfy.sh/", "mytopic", false},
		{"http://ntfy.lan/cake/", "http://ntfy.lan/", "cake", false},
		{"http://host:8080/ntfy/cake?x=1", "http://host:8080/ntfy/", "cake", false},
		{"https://ntfy.sh/", "", "", true},
		{"https://ntfy.sh", "", "", true},
		{"ftp://ntfy.sh/x", "", "", true},
	}
	for _, c := range cases {
		n, err := New(c.url, "")
		if (err != nil) != c.wantErr {
			t.Fatalf("%s: err=%v, wantErr %v", c.url, err, c.wantErr)
		}
		if err == nil && (n.endpoint != c.endpoint || n.topic != c.topic) {
			t.Errorf("%s: endpoint=%q topic=%q, want %q %q", c.url, n.endpoint, n.topic, c.endpoint, c.topic)
		}
	}
	if n, err := New("", "tok"); n != nil || err != nil || n.Enabled() || n.Config().Enabled {
		t.Fatal("empty url must yield a disabled nil notifier")
	}
}

type received struct {
	auth string
	msg  message
}

func TestNotifyFiltersAndPublishes(t *testing.T) {
	var mu sync.Mutex
	var got []received
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m message
		if err := json.Unmarshal(b, &m); err != nil {
			t.Errorf("bad body %q: %v", b, err)
		}
		if r.URL.Path != "/" || r.Method != http.MethodPost {
			t.Errorf("got %s %s, want POST /", r.Method, r.URL.Path)
		}
		mu.Lock()
		got = append(got, received{r.Header.Get("Authorization"), m})
		mu.Unlock()
	}))
	defer srv.Close()

	n, err := New(srv.URL+"/cake", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	n.now = func() time.Time { return now }

	steps := []struct {
		kind, sev, msg string
		queued         bool
	}{
		{"wan", "crit", "WAN session dropped", true},
		{"wan", "ok", "WAN session re-established", false},
		{"satellite", "warn", "RBS50 went offline", false},
		{"orbi", "info", "client joined", false},
		{"wan", "crit", "WAN session dropped", false}, // repeat within 30 min
		{"warp", "warn", "WARP tunnel down", true},
	}
	for _, s := range steps {
		if q := n.Notify(s.kind, s.sev, s.msg); q != s.queued {
			t.Errorf("%s/%s %q: queued=%v, want %v", s.kind, s.sev, s.msg, q, s.queued)
		}
	}
	now = now.Add(31 * time.Minute)
	if !n.Notify("wan", "crit", "WAN session dropped") {
		t.Error("repeat after 30 min should be pushed again")
	}
	n.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("got %d pushes, want 3: %+v", len(got), got)
	}
	byTitle := map[string]received{}
	for _, r := range got {
		if r.auth != "Bearer s3cret" {
			t.Errorf("auth header %q", r.auth)
		}
		byTitle[r.msg.Title] = r
	}
	w := byTitle["router: warp"].msg
	if w.Topic != "cake" || w.Priority != 4 || w.Message != "WARP tunnel down" {
		t.Errorf("warn push = %+v", w)
	}
	c := byTitle["router: wan"].msg
	if c.Priority != 5 || c.Message != "WAN session dropped" {
		t.Errorf("crit push = %+v", c)
	}
}

func TestSendErrorHidesToken(t *testing.T) {
	n, _ := New("http://127.0.0.1:1/topic", "tok-very-secret")
	err := n.send(message{Topic: "topic"})
	if err == nil {
		t.Fatal("want error")
	}
	for _, bad := range []string{"tok-very-secret", "127.0.0.1:1/"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("error %q leaks %q", err, bad)
		}
	}
}
