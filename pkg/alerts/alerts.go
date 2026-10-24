// Package alerts pushes notable events to a phone via ntfy
// (https://ntfy.sh or a self-hosted server).
//
// Every warn/crit event becomes a notification except satellite events
// (the user does not want to be paged when the RBS50 goes down) and
// repeats of the same message within 30 minutes. Nothing is persisted; the
// repeat filter is in memory. The access token is never logged.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	repeatWindow = 30 * time.Minute
	sendTimeout  = 10 * time.Second
)

// ExcludedKind is the event kind that never pages.
const ExcludedKind = "satellite"

// Config is the public, secret-free view served at /api/config.
type Config struct {
	Enabled bool   `json:"enabled"`
	Target  string `json:"target,omitempty"` // "ntfy" when enabled
}

// message is ntfy's JSON publish body. ntfy's JSON API takes the priority
// as an integer: 4 = "high", 5 = "urgent" (max).
type message struct {
	Topic    string   `json:"topic"`
	Title    string   `json:"title"`
	Message  string   `json:"message"`
	Priority int      `json:"priority"`
	Tags     []string `json:"tags,omitempty"`
}

// Notifier publishes events to one ntfy topic. A nil Notifier is valid and
// disabled.
type Notifier struct {
	endpoint string // server root (JSON publishing endpoint)
	topic    string
	host     string // for log lines only
	token    string
	client   *http.Client

	mu       sync.Mutex
	lastSent map[string]time.Time // message → last push
	now      func() time.Time
	wg       sync.WaitGroup
}

// New parses an ntfy topic URL such as https://ntfy.sh/mytopic or
// http://ntfy.lan/cake. The last path segment is the topic; JSON is
// published to the URL with that segment removed (ntfy only accepts JSON
// bodies at the server root — POSTing JSON to /topic would deliver the raw
// JSON as the message text). Returns nil (disabled) for an empty URL and
// an error for an unusable one.
func New(rawURL, token string) (*Notifier, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("alert ntfy url must be http(s)://host/topic")
	}
	path := strings.TrimRight(u.Path, "/")
	i := strings.LastIndexByte(path, '/')
	topic := path[i+1:]
	if topic == "" {
		return nil, errors.New("alert ntfy url has no topic (expected http(s)://host/topic)")
	}
	u.Path = path[:i+1]
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	return &Notifier{
		endpoint: u.String(),
		topic:    topic,
		host:     u.Host,
		token:    token,
		client:   &http.Client{Timeout: sendTimeout},
		lastSent: map[string]time.Time{},
		now:      time.Now,
	}, nil
}

// Enabled reports whether pushes are configured.
func (n *Notifier) Enabled() bool { return n != nil }

// Config returns the UI-facing configuration.
func (n *Notifier) Config() Config {
	if n == nil {
		return Config{}
	}
	return Config{Enabled: true, Target: "ntfy"}
}

// Notify pushes an event asynchronously when it qualifies; it never
// blocks the caller on the network. It reports whether a push was queued.
func (n *Notifier) Notify(kind, sev, msg string) bool {
	if n == nil {
		return false
	}
	m, ok := n.admit(kind, sev, msg)
	if !ok {
		return false
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		if err := n.send(m); err != nil {
			log.Printf("[alerts] ntfy push to %s failed: %s", n.host, err)
		}
	}()
	return true
}

// Wait blocks until in-flight pushes finish (tests, shutdown).
func (n *Notifier) Wait() {
	if n != nil {
		n.wg.Wait()
	}
}

// admit applies the filters and records the message for the repeat window.
func (n *Notifier) admit(kind, sev, msg string) (message, bool) {
	var prio int
	var tags []string
	switch sev {
	case "warn":
		prio, tags = 4, []string{"warning", kind}
	case "crit":
		prio, tags = 5, []string{"rotating_light", kind}
	default:
		return message{}, false
	}
	if kind == ExcludedKind {
		return message{}, false
	}
	now := n.now()
	n.mu.Lock()
	defer n.mu.Unlock()
	if t, seen := n.lastSent[msg]; seen && now.Sub(t) < repeatWindow {
		return message{}, false
	}
	n.lastSent[msg] = now
	for k, t := range n.lastSent { // keep the map bounded
		if now.Sub(t) >= repeatWindow {
			delete(n.lastSent, k)
		}
	}
	return message{Topic: n.topic, Title: "router: " + kind, Message: msg, Priority: prio, Tags: tags}, true
}

func (n *Notifier) send(m message) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("bad request")
	}
	req.Header.Set("Content-Type", "application/json")
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL from the message
		}
		return n.scrub(err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// scrub removes the token from an error string, defensively.
func (n *Notifier) scrub(s string) error {
	if n.token != "" {
		s = strings.ReplaceAll(s, n.token, "***")
	}
	return errors.New(s)
}
