package orbissn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// newSSHDialer returns a dial func opening one SSH client per poll.
//
// Host keys are trusted on first use and pinned in memory for the process
// lifetime: a changed key fails the poll instead of handing the password
// to an impostor. The Orbi's old Dropbear may only offer legacy
// algorithms (diffie-hellman-group1-sha1, aes128-cbc, ssh-rsa), so the
// insecure-but-implemented set is appended after the modern defaults.
func newSSHDialer(addr, user, pass string) func(ctx context.Context) (shell, error) {
	var (
		mu     sync.Mutex
		pinned []byte
	)
	algs, legacy := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				ans := make([]string, len(questions))
				for i := range ans {
					ans[i] = pass
				}
				return ans, nil
			}),
		},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			mu.Lock()
			defer mu.Unlock()
			if pinned == nil {
				pinned = key.Marshal()
				return nil
			}
			if !bytes.Equal(pinned, key.Marshal()) {
				return errors.New("host key changed since first connection")
			}
			return nil
		},
		HostKeyAlgorithms: append(algs.HostKeys, legacy.HostKeys...),
		Timeout:           cmdTimeout,
	}
	cfg.KeyExchanges = append(algs.KeyExchanges, legacy.KeyExchanges...)
	cfg.Ciphers = append(algs.Ciphers, legacy.Ciphers...)
	cfg.MACs = append(algs.MACs, legacy.MACs...)

	return func(ctx context.Context) (shell, error) {
		d := net.Dialer{Timeout: cmdTimeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("connect failed: %w", err)
		}
		_ = conn.SetDeadline(cmdDeadline(ctx))
		c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("handshake/auth failed: %w", err)
		}
		_ = conn.SetDeadline(time.Time{})
		return &sshShell{client: ssh.NewClient(c, chans, reqs), conn: conn}, nil
	}
}

type sshShell struct {
	client *ssh.Client
	conn   net.Conn
}

// Run executes one command in its own session, bounded by cmdTimeout.
func (s *sshShell) Run(ctx context.Context, cmd string) (string, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := sess.CombinedOutput(cmd)
		ch <- result{out, err}
	}()
	tctx, cancel := context.WithDeadline(ctx, cmdDeadline(ctx))
	defer cancel()
	select {
	case r := <-ch:
		return string(r.out), r.err
	case <-tctx.Done():
		sess.Close()
		return "", errors.New("command timed out")
	}
}

func (s *sshShell) Close() error { return s.client.Close() }
