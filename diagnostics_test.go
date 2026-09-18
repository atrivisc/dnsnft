package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const procSample = `    0 2745363674     3 2 65531     7     2       42  1
    5 1234567890     0 2 65531     0     0        9  1
`

func writeProc(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nfnetlink_queue")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadQueueStats(t *testing.T) {
	t.Parallel()
	path := writeProc(t, procSample)

	st, ok, err := readQueueStats(path, 0)
	if err != nil || !ok {
		t.Fatalf("queue 0: ok=%v err=%v", ok, err)
	}
	want := queueStats{port: 2745363674, waiting: 3, dropped: 7, userDropped: 2, queued: 42}
	if st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}

	if _, ok, err := readQueueStats(path, 7); ok || err != nil {
		t.Errorf("queue 7: ok=%v err=%v, want not found", ok, err)
	}
	if _, _, err := readQueueStats(writeProc(t, "0 x 0 2 0 0 0 0 1\n"), 0); err == nil {
		t.Error("a malformed line was accepted")
	}
	if _, _, err := readQueueStats(filepath.Join(t.TempDir(), "missing"), 0); err == nil {
		t.Error("a missing file was accepted")
	}
}

func newTestMonitor(t *testing.T, content string, port uint32) (*queueMonitor, *bytes.Buffer) {
	t.Helper()
	logs := &bytes.Buffer{}
	return &queueMonitor{
		num: 0, port: port, proc: writeProc(t, content),
		verbose: true, logger: log.New(logs, "", 0),
	}, logs
}

func TestQueueMonitor(t *testing.T) {
	t.Parallel()

	t.Run("reports a queue nothing is bound to, once", func(t *testing.T) {
		t.Parallel()
		mon, logs := newTestMonitor(t, "", 2745363674)
		mon.check()
		mon.check()
		if n := strings.Count(logs.String(), "lists no process bound"); n != 1 {
			t.Errorf("logged the warning %d times, want 1", n)
		}
	})

	t.Run("reports a queue bound by someone else", func(t *testing.T) {
		t.Parallel()
		mon, logs := newTestMonitor(t, procSample, 999)
		mon.check()
		if !strings.Contains(logs.String(), "not ours") {
			t.Errorf("log = %q, want the port mismatch in it", logs.String())
		}
	})

	t.Run("reports packets the kernel dropped", func(t *testing.T) {
		t.Parallel()
		mon, logs := newTestMonitor(t, procSample, 2745363674)
		mon.check()
		if !strings.Contains(logs.String(), "dropped 7 packets") {
			t.Errorf("log = %q, want the drops in it", logs.String())
		}
	})

	t.Run("logs activity only when it changes", func(t *testing.T) {
		t.Parallel()
		mon, logs := newTestMonitor(t, procSample, 2745363674)
		mon.check()
		mon.check()
		if n := strings.Count(logs.String(), "42 packets queued so far"); n != 1 {
			t.Errorf("logged the count %d times, want 1", n)
		}
	})

	t.Run("stays quiet without -v", func(t *testing.T) {
		t.Parallel()
		mon, logs := newTestMonitor(t, procSample, 2745363674)
		mon.verbose = false
		mon.check()
		if strings.Contains(logs.String(), "queued so far") {
			t.Errorf("log = %q, want no activity line", logs.String())
		}
	})
}

func TestNfqLogger(t *testing.T) {
	t.Parallel()
	logs := &bytes.Buffer{}
	l := newNfqLogger()
	l.logger = log.New(logs, "", 0)

	l.Debugf("ignored %d", 1)
	for range 5 {
		l.Errorf("Could not parse message: %v", errors.New("invalid header"))
	}
	l.Errorf("Unknown attribute Type: 0x%x", 22)
	if n := strings.Count(logs.String(), "\n"); n != 2 {
		t.Errorf("wrote %d lines, want one per message format:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "nfqueue: Could not parse message: invalid header") {
		t.Errorf("log = %q, want the library message in it", logs.String())
	}

	ctx, cancel := context.WithCancel(context.Background())
	l.ctx = ctx
	cancel()
	logs.Reset()
	l.Errorf("Stop receiving nfqueue messages: %v", ctx.Err())
	if logs.Len() != 0 {
		t.Errorf("log = %q, want shutdown messages dropped", logs.String())
	}
}

func FuzzHandlePacket(f *testing.F) {
	msg := reply("example.com", rr{"example.com", typeA, classIN, 300, a("93.184.216.34")})
	f.Add(udp4Reply(msg))
	f.Add(udp6Reply(msg))
	f.Add(ipv4(6, tcp(50000, 1000, synAck, nil)))
	f.Add(ipv4(6, tcp(50000, 1001, pshAck, framed(msg))))
	f.Add(ipv4(17, udp(53, reply("example.com",
		rr{"example.com", typeCNAME, classIN, 300, wireName("edge.provider.net")}))))
	f.Add([]byte{0x45, 0, 0, 0})
	f.Add([]byte(nil))

	env := newTestDaemon(f)
	f.Fuzz(func(_ *testing.T, data []byte) {
		err := env.handlePacket(data)
		if err != nil {
			return
		}
	})
}
