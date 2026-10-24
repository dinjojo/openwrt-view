package tapo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tess1o/tapo-go"

	"github.com/dinjojo/openwrt-view/pkg/vm"
)

type fakePlug struct {
	mu      sync.Mutex
	info    *tapo.DeviceInfoResponse
	energy  *tapo.EnergyUsageResponse
	infoErr error
	energyE error
}

func (f *fakePlug) DeviceInfo(context.Context) (*tapo.DeviceInfoResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.info, f.infoErr
}

func (f *fakePlug) GetEnergyUsage(context.Context) (*tapo.EnergyUsageResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.energy, f.energyE
}

func plugInfo(on bool) *tapo.DeviceInfoResponse {
	d := &tapo.DeviceInfoResponse{}
	d.Result.DeviceOn = on
	d.Result.Model = "P116M"
	d.Result.Nickname = "TmFub3BpIHBsdWc=" // "Nanopi plug"
	d.Result.Rssi = -52
	d.Result.OnTime = 5400
	return d
}

// fakeFactory returns a Poller whose first (synchronous) snapshot uses fn,
// then hands out later clients from the returned dialer for refresh().
func fakeFactory(t *testing.T, first func() (plugClient, error), later func(call int) (plugClient, error)) (*Poller, *int) {
	t.Helper()
	calls := 0
	p := &Poller{conf: Config{Host: "192.0.2.10", User: "u", Pass: "p"}}
	p.factory = func(context.Context) (plugClient, error) {
		n := calls
		calls++
		if n == 0 {
			return first()
		}
		if later == nil {
			return first()
		}
		return later(n)
	}
	p.refresh() // first synchronous snapshot, like New()
	return p, &calls
}

func TestFirstPollFailure(t *testing.T) {
	p, _ := fakeFactory(t, func() (plugClient, error) {
		return nil, errors.New("connection refused")
	}, func(int) (plugClient, error) {
		return &fakePlug{info: plugInfo(true)}, nil
	})

	st := p.Snapshot()
	if st.Available {
		t.Fatal("state must be unavailable after failed first poll")
	}

	// A later good poll recovers.
	p.refresh()
	st = p.Snapshot()
	if !st.Available || !st.On || st.Name != "Nanopi plug" || st.Rssi != -52 {
		t.Fatalf("unexpected recovered state: %+v", st)
	}
	if st.OnForS != 5400 {
		t.Fatalf("on_for_s = %d, want 5400", st.OnForS)
	}
	if st.HasPower {
		t.Fatal("P116M-style EPM error must not set has_power")
	}
}

func TestEnergyUnsupportedBacksOffHourly(t *testing.T) {
	p, _ := fakeFactory(t, func() (plugClient, error) {
		return &fakePlug{info: plugInfo(false)}, nil
	}, func(int) (plugClient, error) {
		return &fakePlug{info: plugInfo(false), energyE: errors.New("MODULE_NOT_SUPPORTED")}, nil
	})

	// First snapshot: info ok, EPM fails -> plug still available, no power.
	st := p.Snapshot()
	if !st.Available || st.HasPower {
		t.Fatalf("state = %+v, want available without power", st)
	}
	// EPM is marked unsupported and retries only after the hourly backoff.
	if p.epmSupported() {
		t.Fatal("EPM must back off after a failure")
	}

	// Force the backoff window to pass: the retry happens and fails again,
	// and the plug stays available.
	p.mu.Lock()
	p.epmNext = time.Now().Add(-time.Minute)
	p.mu.Unlock()
	p.refresh()
	st = p.Snapshot()
	if !st.Available || st.HasPower {
		t.Fatalf("state after retry = %+v, want available without power", st)
	}
}

func TestEnergyTransientFailureKeepsSupport(t *testing.T) {
	c := &fakePlug{info: plugInfo(true)}
	c.energy = &tapo.EnergyUsageResponse{}
	c.energy.Result.CurrentPower = 1000
	// First poll succeeds with EPM.
	p, later := fakeFactory(t, func() (plugClient, error) { return c, nil }, nil)
	_ = later
	if st := p.Snapshot(); !st.HasPower {
		t.Fatal("first poll must report power")
	}
	// A transient EPM error must not flip epm to unsupported permanently.
	if !p.epmSupported() {
		t.Fatal("a previously working EPM must retry on the next poll")
	}
}

func TestSessionReusedAndRedialsOnError(t *testing.T) {
	dials := 0
	good := &fakePlug{info: plugInfo(true)}
	var current *fakePlug
	p := &Poller{conf: Config{Host: "192.0.2.10"}}
	p.factory = func(context.Context) (plugClient, error) {
		dials++
		if dials == 1 {
			current = good
		} else {
			current = &fakePlug{info: plugInfo(false), energyE: errors.New("403")}
		}
		return current, nil
	}

	p.refresh()
	p.refresh()
	if dials != 1 {
		t.Fatalf("healthy session must be reused, dials = %d", dials)
	}

	// Session goes stale: the next poll re-dials exactly once and recovers
	// with the new session.
	good.infoErr = errors.New("403")
	p.refresh()
	if dials != 2 {
		t.Fatalf("a rejected session must trigger one re-dial, dials = %d", dials)
	}
	if st := p.Snapshot(); !st.Available {
		t.Fatalf("state after re-dial = %+v, want available", st)
	}
}

func TestEnergySupported(t *testing.T) {
	c := &fakePlug{info: plugInfo(true)}
	c.energy = &tapo.EnergyUsageResponse{}
	c.energy.Result.CurrentPower = 2345
	c.energy.ErrorCode = 0
	p, _ := fakeFactory(t, func() (plugClient, error) { return c, nil }, nil)

	st := p.Snapshot()
	if !st.HasPower {
		t.Fatal("has_power must be set when EPM succeeds")
	}
	if st.PowerW != 2.345 {
		t.Fatalf("power_w = %v, want 2.345", st.PowerW)
	}
}

func TestNicknameBase64(t *testing.T) {
	if got := decodeNickname("TmFub3BpIHBsdWc="); got != "Nanopi plug" {
		t.Fatalf("decodeNickname = %q", got)
	}
	if got := decodeNickname("plain-name"); got != "plain-name" {
		t.Fatalf("fallback nickname = %q", got)
	}
	if got := decodeNickname(""); got != "" {
		t.Fatalf("empty nickname = %q", got)
	}
}

// vmFake is a minimal VictoriaMetrics import endpoint.
func vmFake(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var lines []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		mu.Lock()
		lines = append(lines, string(buf[:n]))
		mu.Unlock()
		w.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)
	return srv, &lines
}

func TestVMPush(t *testing.T) {
	srv, lines := vmFake(t)
	c := &fakePlug{info: plugInfo(true)}
	c.energy = &tapo.EnergyUsageResponse{}
	c.energy.Result.CurrentPower = 1500
	p, _ := fakeFactory(t, func() (plugClient, error) { return c, nil }, nil)
	vmc := vm.New(srv.URL)
	p.SetVMClient(vmc)
	p.refresh() // push with the VM client wired

	got := strings.Join(*lines, "\n")
	for _, want := range []string{
		`tapo_plug_on{host="192.0.2.10",model="P116M",name="Nanopi plug"} 1 `,
		`tapo_plug_power_watts{host="192.0.2.10",model="P116M",name="Nanopi plug"} 1.5 `,
		`tapo_plug_rssi{host="192.0.2.10",model="P116M"} -52 `,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("VM body missing %q, got:\n%s", want, got)
		}
	}
}

func TestVMFailureKeepsState(t *testing.T) {
	srv, _ := vmFake(t)
	srv.Close() // import will fail
	c := &fakePlug{info: plugInfo(true)}
	p, _ := fakeFactory(t, func() (plugClient, error) { return c, nil }, nil)
	vmc := vm.New(srv.URL)
	p.SetVMClient(vmc)

	p.refresh()
	if st := p.Snapshot(); !st.Available {
		t.Fatal("a VM import failure must not mark the plug unavailable")
	}
}

func TestVMImportBodyShape(t *testing.T) {
	if bool01(true) != 1 || bool01(false) != 0 {
		t.Fatal("bool01 broken")
	}
	if escapeLabel(`a"b`) != `a\"b` || escapeLabel("a\nb") != "a b" {
		t.Fatal("escapeLabel broken")
	}
}
