package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // IANA zones for -tz on routers without /usr/share/zoneinfo

	"github.com/dinjojo/openwrt-view/pkg/agh"
	"github.com/dinjojo/openwrt-view/pkg/alerts"
	"github.com/dinjojo/openwrt-view/pkg/log"
	"github.com/dinjojo/openwrt-view/pkg/orbi"
	"github.com/dinjojo/openwrt-view/pkg/orbissn"
	"github.com/dinjojo/openwrt-view/pkg/radio"
	"github.com/dinjojo/openwrt-view/pkg/server"
	"github.com/dinjojo/openwrt-view/pkg/tapo"
	"github.com/dinjojo/openwrt-view/pkg/tzloc"
	"github.com/dinjojo/openwrt-view/pkg/usage"
	"github.com/rs/zerolog"
)

// Version is overridden at build-time via -ldflags "-X main.Version=x.y.z".
var Version = "1.0.0"

func main() {
	host := flag.String("host", "0.0.0.0", "bind address for web interface")
	port := flag.Int("port", 11112, "TCP port for web interface")
	interval := flag.Duration("interval", 100*time.Millisecond, "poll interval for tc")
	histCap := flag.Int("history", 300, "samples to retain per interface")
	vmURL := flag.String("vm", "http://127.0.0.1:8428", "VictoriaMetrics base URL for history and health checks (empty disables)")
	orbiURL := flag.String("orbi-url", os.Getenv("ORBI_URL"), "Orbi AP base URL, e.g. http://192.168.1.100 (empty disables Orbi monitoring)")
	orbiUser := flag.String("orbi-user", os.Getenv("ORBI_USER"), "Orbi admin user")
	orbiPass := flag.String("orbi-pass", os.Getenv("ORBI_PASS"), "Orbi admin password")
	// Root-only KEY=VALUE file the binary reads itself: Orbi settings reach
	// the process without appearing in ps, /proc cmdline or ubus.
	orbiConf := flag.String("orbi-conf", os.Getenv("ORBI_CONF"), "KEY=VALUE file with ORBI_URL, ORBI_USER, ORBI_PASS, ORBI_SSH_USER, ORBI_SSH_PASS, ORBI_TELNET_PASS; values already set via flags or environment win")
	// Shell access to the Orbi for per-client radio stats. The host is the
	// -orbi-url host. Never logged; keep the values in a root-only env file.
	orbiSSHUser := flag.String("orbi-ssh-user", os.Getenv("ORBI_SSH_USER"), "Orbi SSH user for per-client Wi-Fi stats (default root when -orbi-ssh-pass is set)")
	orbiSSHPass := flag.String("orbi-ssh-pass", os.Getenv("ORBI_SSH_PASS"), "Orbi SSH password (enables the SSH shell poller; host taken from -orbi-url)")
	orbiTelnetPass := flag.String("orbi-telnet-pass", os.Getenv("ORBI_TELNET_PASS"), "Orbi telnet password (enables telnet shell polling, fallback after SSH; user = -orbi-ssh-user or root)")
	tapoHost := flag.String("tapo-host", os.Getenv("TAPO_HOST"), "Tapo plug host, e.g. 192.168.1.242 (empty disables plug monitoring)")
	tapoUser := flag.String("tapo-user", os.Getenv("TAPO_USER"), "Tapo account email")
	tapoPass := flag.String("tapo-pass", os.Getenv("TAPO_PASS"), "Tapo account password")
	// Root-only KEY=VALUE file, same pattern as -orbi-conf: the Tapo account
	// credentials reach the process without appearing in ps or /proc cmdline.
	tapoConf := flag.String("tapo-conf", os.Getenv("TAPO_CONF"), "KEY=VALUE file with TAPO_HOST, TAPO_USER, TAPO_PASS; values already set via flags or environment win")
	radioIface := flag.String("radio-iface", os.Getenv("RADIO_IFACE"), "local monitor-mode Wi-Fi interface for channel utilisation and neighbour scans, e.g. wlan1 (empty disables)")
	aghURL := flag.String("agh-url", os.Getenv("AGH_URL"), "AdGuard Home base URL, e.g. http://127.0.0.1:8888 (empty disables DNS monitoring)")
	aghUser := flag.String("agh-user", os.Getenv("AGH_USER"), "AdGuard Home dashboard user (a dedicated user, not the admin login)")
	aghPass := flag.String("agh-pass", os.Getenv("AGH_PASS"), "AdGuard Home dashboard password")
	aghConf := flag.String("agh-conf", os.Getenv("AGH_CONF"), "KEY=VALUE file with AGH_URL, AGH_USER, AGH_PASS; values already set via flags or environment win")
	// The ntfy token is never logged; keep it in a root-only env file.
	alertURL := flag.String("alert-ntfy-url", os.Getenv("ALERT_NTFY_URL"), "ntfy topic URL for push alerts on warn/crit events, e.g. https://ntfy.sh/mytopic (empty disables)")
	alertToken := flag.String("alert-ntfy-token", os.Getenv("ALERT_NTFY_TOKEN"), "ntfy access token (sent as Authorization: Bearer)")
	dataDir := flag.String("data-dir", envOr("OPENWRT_VIEW_DATA_DIR", "/opt/monitoring"), "directory for persisted per-client usage files (usage-YYYY-MM-DD.jsonl)")
	// Calendar days (report, usage files) and the probe-schedule awareness
	// of the health check follow this zone. It must match the zone cron
	// runs the probe in. The OpenWrt init script passes the router's zone
	// (uci zonename, else /etc/TZ) as OPENWRT_VIEW_TZ.
	tzName := flag.String("tz", envOr("OPENWRT_VIEW_TZ", "Local"), "time zone for day boundaries and the probe schedule: IANA name (Asia/Kolkata), POSIX string without DST (IST-5:30) or Local")
	showVer := flag.Bool("version", false, "print version and exit")
	ebpfIface := flag.String("acct-ebpf", "", "interface to count per-device traffic on with eBPF (e.g. br-lan; empty disables the spike collector)")
	netifySock := flag.String("netify-sock", envOr("NETIFY_SOCK", "/var/run/netifyd/netifyd.sock"), "netifyd DPI agent's JSON export socket; empty disables the per-app aggregates")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "openwrt-view %s\n\n", Version)
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// Orbi settings from a root-only conf file: any flag or environment
	// value that was set explicitly wins over the file.
	if *orbiConf != "" {
		if conf, err := readKVFile(*orbiConf); err != nil {
			log.Logger.Warn().Err(err).Str("file", *orbiConf).Msg("cannot read -orbi-conf; continuing without it")
		} else {
			explicit := map[string]bool{}
			flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
			for _, e := range []struct {
				key, flag string
				val       *string
			}{
				{"ORBI_URL", "orbi-url", orbiURL},
				{"ORBI_USER", "orbi-user", orbiUser},
				{"ORBI_PASS", "orbi-pass", orbiPass},
				{"ORBI_SSH_USER", "orbi-ssh-user", orbiSSHUser},
				{"ORBI_SSH_PASS", "orbi-ssh-pass", orbiSSHPass},
				{"ORBI_TELNET_PASS", "orbi-telnet-pass", orbiTelnetPass},
			} {
				if v, ok := conf[e.key]; ok && !explicit[e.flag] && *e.val == os.Getenv(e.key) {
					*e.val = v
				}
			}
		}
	}

	// Tapo settings from a root-only conf file, same precedence as Orbi's.
	if *tapoConf != "" {
		if conf, err := readKVFile(*tapoConf); err != nil {
			log.Logger.Warn().Err(err).Str("file", *tapoConf).Msg("cannot read -tapo-conf; continuing without it")
		} else {
			explicit := map[string]bool{}
			flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
			for _, e := range []struct {
				key, flag string
				val       *string
			}{
				{"TAPO_HOST", "tapo-host", tapoHost},
				{"TAPO_USER", "tapo-user", tapoUser},
				{"TAPO_PASS", "tapo-pass", tapoPass},
			} {
				if v, ok := conf[e.key]; ok && !explicit[e.flag] && *e.val == os.Getenv(e.key) {
					*e.val = v
				}
			}
		}
	}

	// AdGuard Home settings from a root-only conf file, same precedence
	// as Orbi's and Tapo's.
	if *aghConf != "" {
		if conf, err := readKVFile(*aghConf); err != nil {
			log.Logger.Warn().Err(err).Str("file", *aghConf).Msg("cannot read -agh-conf; continuing without it")
		} else {
			explicit := map[string]bool{}
			flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
			for _, e := range []struct {
				key, flag string
				val       *string
			}{
				{"AGH_URL", "agh-url", aghURL},
				{"AGH_USER", "agh-user", aghUser},
				{"AGH_PASS", "agh-pass", aghPass},
			} {
				if v, ok := conf[e.key]; ok && !explicit[e.flag] && *e.val == os.Getenv(e.key) {
					*e.val = v
				}
			}
		}
	}

	if *showVer {
		fmt.Printf("openwrt-view %s\n", Version)
		os.Exit(0)
	}

	addr := fmt.Sprintf("%s:%d", *host, *port)
	log.Logger = log.Logger.Level(zerolog.InfoLevel).With().Str("version", Version).Logger()

	loc, err := tzloc.Load(*tzName)
	if err != nil {
		log.Logger.Warn().Err(err).Msg("bad -tz / OPENWRT_VIEW_TZ; falling back to the process local zone")
		loc = time.Local
	}
	// Make the zone process-wide too, so every formatted time (health
	// details, logs) agrees with the day boundaries. Done before any
	// goroutine starts.
	time.Local = loc
	zone, off := time.Now().In(loc).Zone()
	tzEv := log.Logger.Info().Str("tz", loc.String()).Str("zone", zone).Int("utc_offset_s", off).Str("env_TZ", os.Getenv("TZ"))
	if off == 0 && *tzName == "Local" {
		tzEv = tzEv.Str("hint", "process zone resolved to UTC; set OPENWRT_VIEW_TZ (e.g. Asia/Kolkata) so report days and the probe schedule match the router")
	}
	tzEv.Msg("time zone")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(addr, *interval, *histCap, *vmURL, Version, orbi.New(*orbiURL, *orbiUser, *orbiPass, nil))
	srv.SetLocation(loc)
	orbiHost := ""
	if u, err := url.Parse(*orbiURL); err == nil && *orbiURL != "" {
		orbiHost = u.Hostname()
	}
	srv.SetShellPoller(orbissn.New(orbissn.Config{
		Host:       orbiHost,
		SSHUser:    *orbiSSHUser,
		SSHPass:    *orbiSSHPass,
		TelnetPass: *orbiTelnetPass,
	}))
	srv.SetRadioCollector(radio.New(*radioIface))
	if *ebpfIface != "" {
		if err := srv.EnableEBPFAcct(*ebpfIface); err != nil {
			log.Logger.Warn().Err(err).Str("iface", *ebpfIface).Msg("eBPF accounting unavailable; continuing without it")
		}
	}
	srv.EnableNetify(*netifySock)
	if *tapoHost != "" {
		srv.SetTapoPoller(tapo.New(tapo.Config{Host: *tapoHost, User: *tapoUser, Pass: *tapoPass}, nil))
		log.Logger.Info().Str("host", *tapoHost).Msg("Tapo plug monitoring enabled")
	}
	if *aghURL != "" {
		srv.SetAGH(agh.New(agh.Config{URL: *aghURL, User: *aghUser, Pass: *aghPass}))
		log.Logger.Info().Str("url", *aghURL).Msg("AdGuard Home monitoring enabled")
	}
	notifier, err := alerts.New(*alertURL, *alertToken)
	if err != nil {
		log.Logger.Warn().Err(err).Msg("push alerts disabled")
	}
	srv.SetAlerts(notifier)
	if *dataDir != "" {
		us := usage.New(*dataDir)
		us.SetLocation(loc)
		srv.SetUsageStore(us)
	}
	if err := srv.Run(ctx, addr); err != nil {
		log.Logger.Fatal().Err(err).Msg("fatal")
	}
	log.Logger.Info().Msg("shutdown complete")
}

// envOr returns the environment variable or a default when it is unset.
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// readKVFile parses a KEY=VALUE file (comments with #, blank lines ignored).
func readKVFile(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, nil
}
