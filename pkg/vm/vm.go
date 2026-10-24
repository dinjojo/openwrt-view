// Package vm provides a minimal client for the VictoriaMetrics HTTP API
// (instant queries and range queries) used by the health evaluator and the
// long-range history endpoint.
package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client talks to a VictoriaMetrics single-node instance.
type Client struct {
	BaseURL string // e.g. http://127.0.0.1:8428
	HTTP    *http.Client
}

// New returns a Client with sane timeouts.
func New(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

// Series is one labelled time series with its data points.
type Series struct {
	Labels map[string]string
	TS     []int64   // unix seconds
	Val    []float64 // sample values, parallel to TS
}

// Point is a single labelled sample (instant queries).
type Point struct {
	Labels map[string]string
	TS     int64
	Val    float64
}

type apiVectorResult struct {
	Metric map[string]string `json:"metric"`
	Value  []interface{}     `json:"value"`
}

type apiMatrixResult struct {
	Metric map[string]string `json:"metric"`
	Values [][]interface{}   `json:"values"`
}

type apiResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string            `json:"resultType"`
		Result     []json.RawMessage `json:"result"`
	} `json:"data"`
	Error string `json:"error,omitempty"`
}

// Query runs an instant query and returns the resulting vector.
func (c *Client) Query(ctx context.Context, query string) ([]Point, error) {
	return c.fetch(ctx, c.BaseURL+"/api/v1/query?query="+url.QueryEscape(query), decodeVector)
}

// QueryAt runs an instant query evaluated at the given unix second.
func (c *Client) QueryAt(ctx context.Context, query string, ts int64) ([]Point, error) {
	u := c.BaseURL + "/api/v1/query?query=" + url.QueryEscape(query) + "&time=" + strconv.FormatInt(ts, 10)
	return c.fetch(ctx, u, decodeVector)
}

// QueryRaw returns the raw samples of selector stored in [start, end] with
// their ORIGINAL timestamps, one Series per label set. It evaluates the
// range-vector selector `selector[<window>]` as an instant query at end,
// which VictoriaMetrics (like Prometheus) answers with the stored samples
// rather than step-aligned points.
//
// Use it whenever the sample time matters: instant queries report the
// query time (Point.TS is "now" for every sample still inside the
// lookback window) and range queries report step-grid times with values
// carried forward, so neither can tell "a new probe ran" from "the same
// probe is still visible".
func (c *Client) QueryRaw(ctx context.Context, selector string, start, end int64) ([]Series, error) {
	window := end - start + 1 // the selector window is left-open; +1 keeps start inclusive
	if window < 1 {
		window = 1
	}
	q := selector + "[" + strconv.FormatInt(window, 10) + "s]"
	u := c.BaseURL + "/api/v1/query?query=" + url.QueryEscape(q) + "&time=" + strconv.FormatInt(end, 10)
	return c.fetchRange(ctx, u)
}

func decodeVector(raw json.RawMessage) ([]Point, error) {
	var r apiVectorResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	p := Point{Labels: r.Metric}
	if len(r.Value) == 2 {
		if ts, ok := r.Value[0].(float64); ok {
			p.TS = int64(ts)
		}
		if v, ok := r.Value[1].(string); ok {
			p.Val, _ = strconv.ParseFloat(v, 64)
		}
	}
	return []Point{p}, nil
}

// QueryRange runs a range query and returns one Series per label set.
func (c *Client) QueryRange(ctx context.Context, query string, start, end int64, step string) ([]Series, error) {
	u := fmt.Sprintf("%s/api/v1/query_range?query=%s&start=%d&end=%d&step=%s",
		c.BaseURL, url.QueryEscape(query), start, end, url.QueryEscape(step))
	return c.fetchRange(ctx, u)
}

func (c *Client) do(ctx context.Context, u string) (*apiResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var api apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&api); err != nil {
		return nil, err
	}
	if api.Status != "success" {
		return nil, fmt.Errorf("vm query failed: %s", api.Error)
	}
	return &api, nil
}

func (c *Client) fetch(ctx context.Context, u string, decode func(json.RawMessage) ([]Point, error)) ([]Point, error) {
	api, err := c.do(ctx, u)
	if err != nil {
		return nil, err
	}
	var out []Point
	for _, raw := range api.Data.Result {
		pts, err := decode(raw)
		if err != nil {
			continue
		}
		out = append(out, pts...)
	}
	return out, nil
}

func (c *Client) fetchRange(ctx context.Context, u string) ([]Series, error) {
	api, err := c.do(ctx, u)
	if err != nil {
		return nil, err
	}
	var out []Series
	for _, raw := range api.Data.Result {
		var r apiMatrixResult
		if err := json.Unmarshal(raw, &r); err != nil {
			continue
		}
		s := Series{Labels: r.Metric, TS: make([]int64, 0, len(r.Values)), Val: make([]float64, 0, len(r.Values))}
		for _, v := range r.Values {
			if len(v) != 2 {
				continue
			}
			ts, _ := v[0].(float64)
			// The sample value must be a JSON string; null or a number
			// would panic on a bare assertion, so skip malformed pairs.
			vs, ok := v[1].(string)
			if !ok {
				continue
			}
			val, _ := strconv.ParseFloat(vs, 64)
			s.TS = append(s.TS, int64(ts))
			s.Val = append(s.Val, val)
		}
		out = append(out, s)
	}
	return out, nil
}

// Import pushes Prometheus text-format samples into VictoriaMetrics.
func (c *Client) Import(ctx context.Context, body string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/api/v1/import/prometheus", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("import failed: HTTP %d", resp.StatusCode)
	}
	return nil
}
