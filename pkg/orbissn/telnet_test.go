package orbissn

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeTelnetd mimics busybox telnetd + ash on the Orbi: proposes ECHO,
// asks login/password, echoes typed lines, and answers wlanconfig.
func fakeTelnetd(t *testing.T, wantPass string, gotReply chan<- []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte{tIAC, tWILL, 1, tIAC, tDO, 31}) // WILL ECHO, DO NAWS
		reply := make([]byte, 6)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(reply); err == nil {
			gotReply <- reply
		}
		r := bufio.NewReader(c)
		c.Write([]byte("\r\nRBR50 login: "))
		r.ReadString('\n')
		c.Write([]byte("Password: "))
		pass, _ := r.ReadString('\n')
		if strings.TrimSpace(pass) != wantPass {
			c.Write([]byte("\r\nLogin incorrect\r\nRBR50 login: "))
			return
		}
		c.Write([]byte("\r\n\r\nBusyBox v1.25 built-in shell (ash)\r\nroot@RBR50:/# "))
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			c.Write([]byte(line + "\r\n")) // terminal echo
			out, rc := "", "1"
			switch {
			case strings.HasPrefix(line, readyCmd):
				out, rc = "__CSREADY__\r\n", ""
			case strings.HasPrefix(line, "wlanconfig ath1 list sta"):
				out, rc = strings.ReplaceAll(fixtureFull, "\n", "\r\n"), "0"
			case strings.HasPrefix(line, "wlanconfig ath0 list sta"):
				out, rc = "", "0" // no 2.4 GHz clients
			case strings.HasPrefix(line, "exit"):
				return
			}
			if rc != "" {
				out += "__CSEND__" + rc + "\r\n"
			}
			c.Write([]byte(out + "root@RBR50:/# "))
		}
	}()
	return ln.Addr().String()
}

func TestTelnetPoll(t *testing.T) {
	replies := make(chan []byte, 1)
	addr := fakeTelnetd(t, "s3cret-pass", replies)
	p := &Poller{transports: []transport{{"telnet", newTelnetDialer(addr, "root", "s3cret-pass")}}}
	snap := p.poll(context.Background())
	if !snap.Shell.OK || snap.Shell.Via != "telnet" {
		t.Fatalf("shell status = %+v", snap.Shell)
	}
	if got := <-replies; string(got) != string([]byte{tIAC, tDONT, 1, tIAC, tWONT, 31}) {
		t.Errorf("negotiation reply = %v, want DONT ECHO / WONT NAWS", got)
	}
	st, ok := snap.Stations["98:3A:C3:12:34:56"]
	if !ok || len(snap.Stations) != 2 {
		t.Fatalf("stations = %+v", snap.Stations)
	}
	if st.Band != "5G" || *st.TxRate != 780 || st.Mode != "11AC_VHT80" {
		t.Errorf("station = %+v", st)
	}
}

func TestTelnetBadPasswordErrorHasNoSecret(t *testing.T) {
	addr := fakeTelnetd(t, "right-pass", make(chan []byte, 1))
	p := New(Config{Host: "unused", TelnetPass: "wrong-pass-123"})
	p.transports[0].dial = newTelnetDialer(addr, "root", "wrong-pass-123")
	snap := p.poll(context.Background())
	if snap.Shell.OK || snap.Shell.Err == "" {
		t.Fatalf("expected failure, got %+v", snap.Shell)
	}
	if strings.Contains(snap.Shell.Err, "wrong-pass-123") {
		t.Fatalf("error leaks the password: %q", snap.Shell.Err)
	}
	if !strings.Contains(snap.Shell.Err, "login rejected") {
		t.Errorf("err = %q, want login rejected", snap.Shell.Err)
	}
}

func TestUnconfiguredSnapshot(t *testing.T) {
	var nilP *Poller
	for _, p := range []*Poller{nilP, New(Config{Host: "192.168.1.100"})} {
		if p.Enabled() {
			t.Fatal("unconfigured poller reports enabled")
		}
		s := p.Snapshot()
		if s.Stations == nil || s.Shell != (Status{}) {
			t.Errorf("snapshot = %+v", s)
		}
	}
}
