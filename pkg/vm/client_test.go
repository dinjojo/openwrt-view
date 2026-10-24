package vm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeVM records the last request and answers with a fixed status/body.
type fakeVM struct {
	status  int
	body    string
	path    string
	params  url.Values
	method  string
	ctype   string
	reqBody string
}

func (f *fakeVM) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.path, f.params, f.method = r.URL.Path, r.URL.Query(), r.Method
		f.ctype = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		f.reqBody = string(b)
		if f.status != 0 {
			w.WriteHeader(f.status)
		}
		io.WriteString(w, f.body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNewDefaults(t *testing.T) {
	c := New("http://127.0.0.1:8428")
	if c.BaseURL != "http://127.0.0.1:8428" || c.HTTP == nil || c.HTTP.Timeout != 15*time.Second {
		t.Fatalf("New() = %+v", c)
	}
}

func TestQuery(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr bool
		want    []Point
	}{
		{
			name: "vector with two series",
			body: `{"status":"success","data":{"resultType":"vector","result":[` +
				`{"metric":{"__name__":"up","job":"a"},"value":[1700000000.25,"1"]},` +
				`{"metric":{"job":"b"},"value":[1700000000,"0.5"]}]}}`,
			want: []Point{
				{Labels: map[string]string{"__name__": "up", "job": "a"}, TS: 1700000000, Val: 1},
				{Labels: map[string]string{"job": "b"}, TS: 1700000000, Val: 0.5},
			},
		},
		{
			name: "empty result",
			body: `{"status":"success","data":{"resultType":"vector","result":[]}}`,
			want: nil,
		},
		{
			name: "malformed entry skipped, bad value tolerated",
			body: `{"status":"success","data":{"resultType":"vector","result":[` +
				`"not an object",` +
				`{"metric":{"k":"v"},"value":[1700000001,"NaNish"]},` +
				`{"metric":{"k":"short"},"value":[1]}]}}`,
			want: []Point{
				{Labels: map[string]string{"k": "v"}, TS: 1700000001, Val: 0},
				{Labels: map[string]string{"k": "short"}},
			},
		},
		{
			name:    "error status",
			status:  http.StatusBadRequest,
			body:    `{"status":"error","errorType":"bad_data","error":"parse error"}`,
			wantErr: true,
		},
		{
			name:    "non-200 with HTML body",
			status:  http.StatusBadGateway,
			body:    `<html>bad gateway</html>`,
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			body:    `{"status":"success","data":`,
			wantErr: true,
		},
		{
			name:    "empty body",
			body:    ``,
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeVM{status: tc.status, body: tc.body}
			srv := f.server(t)
			got, err := New(srv.URL).Query(context.Background(), `rate(x{a="b c"}[5m])`)
			if f.path != "/api/v1/query" || f.params.Get("query") != `rate(x{a="b c"}[5m])` || f.params.Has("time") {
				t.Errorf("request path=%q params=%v", f.path, f.params)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !pointsEqual(got, tc.want) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestQueryErrorMessageIncludesServerError(t *testing.T) {
	f := &fakeVM{status: http.StatusUnprocessableEntity, body: `{"status":"error","error":"cannot parse query"}`}
	srv := f.server(t)
	_, err := New(srv.URL).Query(context.Background(), "x{")
	if err == nil || !strings.Contains(err.Error(), "cannot parse query") {
		t.Fatalf("err = %v", err)
	}
}

func TestQueryAt(t *testing.T) {
	f := &fakeVM{body: `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1234,"7"]}]}}`}
	srv := f.server(t)
	got, err := New(srv.URL).QueryAt(context.Background(), "up", 1234)
	if err != nil {
		t.Fatal(err)
	}
	if f.params.Get("query") != "up" || f.params.Get("time") != "1234" {
		t.Errorf("params = %v", f.params)
	}
	if len(got) != 1 || got[0].TS != 1234 || got[0].Val != 7 {
		t.Errorf("got %+v", got)
	}
}

func TestQueryRange(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr bool
		want    []Series
	}{
		{
			name: "matrix with two series",
			body: `{"status":"success","data":{"resultType":"matrix","result":[` +
				`{"metric":{"iface":"eth0"},"values":[[100,"1.5"],[160,"2"],[220,"-3"]]},` +
				`{"metric":{"iface":"eth1"},"values":[[100,"0"]]}]}}`,
			want: []Series{
				{Labels: map[string]string{"iface": "eth0"}, TS: []int64{100, 160, 220}, Val: []float64{1.5, 2, -3}},
				{Labels: map[string]string{"iface": "eth1"}, TS: []int64{100}, Val: []float64{0}},
			},
		},
		{
			name: "empty matrix",
			body: `{"status":"success","data":{"resultType":"matrix","result":[]}}`,
		},
		{
			name: "series with no values and short pairs",
			body: `{"status":"success","data":{"resultType":"matrix","result":[` +
				`{"metric":{"a":"1"},"values":[]},` +
				`{"metric":{"a":"2"},"values":[[100],[200,"4"],[300,"5",1]]},` +
				`42]}}`,
			want: []Series{
				{Labels: map[string]string{"a": "1"}, TS: []int64{}, Val: []float64{}},
				{Labels: map[string]string{"a": "2"}, TS: []int64{200}, Val: []float64{4}},
			},
		},
		{
			name:    "error status",
			status:  http.StatusBadRequest,
			body:    `{"status":"error","error":"step too small"}`,
			wantErr: true,
		},
		{
			name:    "non-200 with text body",
			status:  http.StatusServiceUnavailable,
			body:    `service unavailable`,
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			body:    `{"status":`,
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeVM{status: tc.status, body: tc.body}
			srv := f.server(t)
			got, err := New(srv.URL).QueryRange(context.Background(), `sum by (iface) (x{y="z"})`, 100, 400, "1m")
			if f.path != "/api/v1/query_range" {
				t.Errorf("path = %q", f.path)
			}
			for k, want := range map[string]string{"query": `sum by (iface) (x{y="z"})`, "start": "100", "end": "400", "step": "1m"} {
				if g := f.params.Get(k); g != want {
					t.Errorf("param %s = %q, want %q", k, g, want)
				}
			}
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !seriesEqual(got, tc.want) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestQueryRangeEscapesStep(t *testing.T) {
	f := &fakeVM{body: `{"status":"success","data":{"resultType":"matrix","result":[]}}`}
	srv := f.server(t)
	if _, err := New(srv.URL).QueryRange(context.Background(), "a+b", 1, 2, "1m&evil=1"); err != nil {
		t.Fatal(err)
	}
	if f.params.Get("step") != "1m&evil=1" || f.params.Has("evil") || f.params.Get("query") != "a+b" {
		t.Errorf("params = %v", f.params)
	}
}

func TestQueryRawWindow(t *testing.T) {
	cases := []struct {
		name       string
		start, end int64
		wantQuery  string
		wantTime   string
	}{
		{"one hour", 1000, 4600, "m[3601s]", "4600"},
		{"single second", 50, 50, "m[1s]", "50"},
		{"inverted range clamps to 1s", 100, 10, "m[1s]", "10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeVM{body: `{"status":"success","data":{"resultType":"matrix","result":[]}}`}
			srv := f.server(t)
			got, err := New(srv.URL).QueryRaw(context.Background(), "m", tc.start, tc.end)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 0 {
				t.Errorf("want empty, got %+v", got)
			}
			if f.path != "/api/v1/query" || f.params.Get("query") != tc.wantQuery || f.params.Get("time") != tc.wantTime {
				t.Errorf("path=%q params=%v", f.path, f.params)
			}
		})
	}
}

func TestQueryRawErrors(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"error status", `{"status":"error","error":"boom"}`},
		{"malformed", `nope`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeVM{body: tc.body}
			srv := f.server(t)
			if _, err := New(srv.URL).QueryRaw(context.Background(), "m", 1, 2); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestQueryTransportErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	base := srv.URL
	srv.Close() // nothing listening any more

	c := New(base)
	if _, err := c.Query(context.Background(), "up"); err == nil {
		t.Error("Query: want connection error")
	}
	if _, err := c.QueryRange(context.Background(), "up", 1, 2, "1s"); err == nil {
		t.Error("QueryRange: want connection error")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fakeVM{body: `{"status":"success","data":{"result":[]}}`}
	live := f.server(t)
	if _, err := New(live.URL).Query(ctx, "up"); err == nil {
		t.Error("cancelled context: want error")
	}

	if _, err := New("http://bad host\x7f").Query(context.Background(), "up"); err == nil {
		t.Error("invalid base URL: want error")
	}
}

func TestImport(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{"204 ok", http.StatusNoContent, false},
		{"200 ok", http.StatusOK, false},
		{"400 fails", http.StatusBadRequest, true},
		{"500 fails", http.StatusInternalServerError, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeVM{status: tc.status}
			srv := f.server(t)
			body := "m{a=\"b\"} 1 1700000000000\n"
			err := New(srv.URL).Import(context.Background(), body)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if f.method != http.MethodPost || f.path != "/api/v1/import/prometheus" || f.ctype != "text/plain" || f.reqBody != body {
				t.Errorf("request method=%s path=%s ctype=%s body=%q", f.method, f.path, f.ctype, f.reqBody)
			}
		})
	}
}

func labelsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func pointsEqual(a, b []Point) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].TS != b[i].TS || a[i].Val != b[i].Val || !labelsEqual(a[i].Labels, b[i].Labels) {
			return false
		}
	}
	return true
}

func seriesEqual(a, b []Series) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !labelsEqual(a[i].Labels, b[i].Labels) || len(a[i].TS) != len(b[i].TS) || len(a[i].Val) != len(b[i].Val) {
			return false
		}
		for j := range a[i].TS {
			if a[i].TS[j] != b[i].TS[j] || a[i].Val[j] != b[i].Val[j] {
				return false
			}
		}
	}
	return true
}
