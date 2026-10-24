package vm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryRawKeepsSampleTimestamps(t *testing.T) {
	var gotQuery, gotTime string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery, gotTime = r.URL.Query().Get("query"), r.URL.Query().Get("time")
		w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[` +
			`{"metric":{"__name__":"probe_bloat_ms","direction":"down"},"values":[[1792651228.5,"3.1"],[1792654829,"42"]]}]}}`))
	}))
	defer srv.Close()

	series, err := New(srv.URL).QueryRaw(context.Background(), `probe_bloat_ms{direction="down"}`, 1792650000, 1792655000)
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != `probe_bloat_ms{direction="down"}[5001s]` || gotTime != "1792655000" {
		t.Errorf("query = %q time = %q", gotQuery, gotTime)
	}
	if len(series) != 1 || len(series[0].TS) != 2 || series[0].TS[0] != 1792651228 || series[0].TS[1] != 1792654829 || series[0].Val[1] != 42 {
		t.Errorf("series = %+v", series)
	}
}
