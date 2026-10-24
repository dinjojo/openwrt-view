package orbissn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Telnet protocol bytes (RFC 854).
const (
	tIAC  = 255
	tDONT = 254
	tDO   = 253
	tWONT = 252
	tWILL = 251
	tSB   = 250
	tSE   = 240
)

// Markers are typed with an empty "" pair inside so the terminal echo of
// the command line never matches the marker the shell actually prints.
const (
	readyCmd  = `echo __CS""READY__`
	readyMark = "__CSREADY__"
	endCmd    = `; echo __CS""END__$?`
	endMark   = "__CSEND__"
)

// newTelnetDialer returns a dial func that logs in over raw telnet
// (addr is host:23), refusing every option the server proposes.
func newTelnetDialer(addr, user, pass string) func(ctx context.Context) (shell, error) {
	return func(ctx context.Context) (shell, error) {
		d := net.Dialer{Timeout: cmdTimeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("connect failed: %w", err)
		}
		t := &telnetShell{conn: conn}
		if err := t.login(ctx, user, pass); err != nil {
			conn.Close()
			return nil, err
		}
		return t, nil
	}
}

type telnetShell struct {
	conn    net.Conn
	pending []byte // decoded data not yet consumed
	state   int    // IAC parser state, kept across reads
	verb    byte
}

func (t *telnetShell) login(ctx context.Context, user, pass string) error {
	i, _, err := t.readUntil(ctx, "login:", "assword:", "# ", "$ ")
	if err != nil {
		return errors.New("telnet: no login prompt")
	}
	if i == 0 {
		if err := t.send(user); err != nil {
			return err
		}
		if i, _, err = t.readUntil(ctx, "assword:", "# ", "$ "); err != nil {
			return errors.New("telnet: no password prompt")
		}
		i++ // align with the outer indices: 1 = password prompt
	}
	if i == 1 {
		if err := t.send(pass); err != nil {
			return err
		}
	}
	t.pending = nil
	if err := t.send(readyCmd); err != nil {
		return err
	}
	i, _, err = t.readUntil(ctx, readyMark, "ncorrect", "login:", "denied")
	if err != nil {
		return errors.New("telnet: no shell after login")
	}
	if i != 0 {
		return errors.New("telnet: login rejected")
	}
	t.pending = nil
	return nil
}

// Run sends one command and returns its output, using an echo marker
// carrying the exit status to find the end of output.
func (t *telnetShell) Run(ctx context.Context, cmd string) (string, error) {
	t.pending = nil
	if err := t.send(cmd + " 2>&1" + endCmd); err != nil {
		return "", err
	}
	_, data, err := t.readUntil(ctx, endMark)
	if err != nil {
		return "", errors.New("command timed out")
	}
	_, rc, err := t.readUntil(ctx, "\n")
	if err != nil {
		return "", errors.New("command timed out")
	}
	out := strings.TrimSuffix(data, endMark)
	// Drop the terminal's echo of the typed command line.
	if i := strings.Index(out, `__CS""END__`); i >= 0 {
		if nl := strings.IndexByte(out[i:], '\n'); nl >= 0 {
			out = out[i+nl+1:]
		} else {
			out = ""
		}
	}
	if code, cerr := strconv.Atoi(strings.TrimSpace(rc)); cerr != nil || code != 0 {
		return out, fmt.Errorf("exit status %s", strings.TrimSpace(rc))
	}
	return out, nil
}

func (t *telnetShell) Close() error {
	_ = t.conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = t.conn.Write([]byte("exit\r\n"))
	return t.conn.Close()
}

func (t *telnetShell) send(line string) error {
	_ = t.conn.SetWriteDeadline(time.Now().Add(cmdTimeout))
	if _, err := t.conn.Write([]byte(line + "\r\n")); err != nil {
		return errors.New("telnet: write failed")
	}
	return nil
}

// readUntil reads until one of the markers appears in the decoded stream.
// It returns the index of the first marker found (earliest position), the
// data up to and including it, and keeps the remainder pending.
func (t *telnetShell) readUntil(ctx context.Context, markers ...string) (int, string, error) {
	_ = t.conn.SetReadDeadline(cmdDeadline(ctx))
	buf := make([]byte, 4096)
	for {
		best, bestPos := -1, -1
		s := string(t.pending)
		for i, m := range markers {
			if p := strings.Index(s, m); p >= 0 && (bestPos < 0 || p < bestPos) {
				best, bestPos = i, p
			}
		}
		if best >= 0 {
			end := bestPos + len(markers[best])
			data := s[:end]
			t.pending = []byte(s[end:])
			return best, data, nil
		}
		n, err := t.conn.Read(buf)
		if n > 0 {
			t.decode(buf[:n])
		}
		if err != nil {
			return -1, "", err
		}
	}
}

// decode strips telnet commands from raw bytes into pending, answering
// DO with WONT and WILL with DONT.
func (t *telnetShell) decode(raw []byte) {
	var reply []byte
	for _, b := range raw {
		switch t.state {
		case 0: // data
			if b == tIAC {
				t.state = 1
			} else if b != 0 {
				t.pending = append(t.pending, b)
			}
		case 1: // after IAC
			switch b {
			case tIAC:
				t.pending = append(t.pending, b)
				t.state = 0
			case tDO, tDONT, tWILL, tWONT:
				t.verb, t.state = b, 2
			case tSB:
				t.state = 3
			default:
				t.state = 0
			}
		case 2: // option byte
			switch t.verb {
			case tDO:
				reply = append(reply, tIAC, tWONT, b)
			case tWILL:
				reply = append(reply, tIAC, tDONT, b)
			}
			t.state = 0
		case 3: // subnegotiation
			if b == tIAC {
				t.state = 4
			}
		case 4:
			if b == tSE {
				t.state = 0
			} else {
				t.state = 3
			}
		}
	}
	if len(reply) > 0 {
		_ = t.conn.SetWriteDeadline(time.Now().Add(cmdTimeout))
		_, _ = t.conn.Write(reply)
	}
}
