package health

import (
	"context"
	"strings"
	"testing"
)

// The accounting check must catch the nlbwmon stall observed live on the
// router: client counters frozen at byte-identical values for hours while
// the WAN kept moving — every per-device panel silently reads 0.
func TestEvalAccounting(t *testing.T) {
	const (
		wanQ = `sum(increase(node_network_receive_bytes_total{device="pppoe-wan"}[10m]))` +
			` + sum(increase(node_network_transmit_bytes_total{device="pppoe-wan"}[10m]))`
		cliQ = `sum(increase(client_bytes_total[10m]))`
	)
	cases := []struct {
		name     string
		vm       *fakeVM
		state    State
		contains []string
	}{
		{"query error is unknown", &fakeVM{fail: map[string]bool{wanQ: true}},
			StateUnknown, []string{"cannot verify"}},
		{"quiet WAN proves nothing", &fakeVM{data: map[string][]sample{
			wanQ: v(4e6), cliQ: v(0)}},
			StateOK, []string{"nearly silent"}},
		{"stuck: WAN traffic, frozen counters", &fakeVM{data: map[string][]sample{
			wanQ: v(2.4e9), cliQ: v(0)}},
			StateWarn, []string{"nlbwmon's accounting is stuck", "nlbwmon restart"}},
		{"live: counters track the WAN", &fakeVM{data: map[string][]sample{
			wanQ: v(2.4e9), cliQ: v(2.0e9)}},
			StateOK, []string{"attributing traffic per device"}},
		{"trace counter growth still counts as live", &fakeVM{data: map[string][]sample{
			wanQ: v(5e6), cliQ: v(2048)}},
			StateOK, []string{"attributing traffic per device"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalAccounting(context.Background(), c.vm.client(t))
			if got.State != c.state {
				t.Errorf("state = %q, want %q (detail: %s)", got.State, c.state, got.Detail)
			}
			for _, s := range c.contains {
				if !strings.Contains(got.Detail, s) {
					t.Errorf("detail %q does not contain %q", got.Detail, s)
				}
			}
		})
	}
	checkCommon(t, evalAccounting(context.Background(), nil), "Per-device accounting", want{state: StateUnknown})
}
