package main

import (
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/google/nftables"
)

func TestAddElemTimeout(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name   string
		extra  time.Duration
		maxTTL time.Duration
		ttl    uint32
		want   time.Duration
	}{
		{"ttl plus the grace period", 48 * time.Hour, 24 * time.Hour, 300, 48*time.Hour + 5*time.Minute},
		{"a long ttl is capped first", 48 * time.Hour, 24 * time.Hour, 86400 * 100, 72 * time.Hour},
		{"zero ttl leaves the grace period", 48 * time.Hour, 24 * time.Hour, 0, 48 * time.Hour},
		{"a ttl over MaxInt32 counts as zero", 48 * time.Hour, 24 * time.Hour, 1 << 31, 48 * time.Hour},
		{"never shorter than a second", 0, 0, 0, time.Second},
		{"sub-second totals round up to a second", 1500 * time.Millisecond, 0, 0, time.Second},
		{"truncated to whole seconds", 1500 * time.Millisecond, time.Hour, 10, 11 * time.Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			env := newTestDaemon(t, func(cfg *config) { cfg.extra, cfg.maxTTL = c.extra, c.maxTTL })
			got := env.addElem(nil, a("1.2.3.4"), c.ttl)
			if len(got) != 1 || got[0].Timeout != c.want {
				t.Fatalf("timeout = %v, want %v", got[0].Timeout, c.want)
			}
		})
	}
}

func TestAddElemDeduplicates(t *testing.T) {
	t.Parallel()
	env := newTestDaemon(t)
	list := env.addElem(nil, a("1.2.3.4"), 10)
	list = env.addElem(list, a("1.2.3.4"), 7200)
	list = env.addElem(list, a("1.2.3.4"), 5)
	list = env.addElem(list, a("5.6.7.8"), 10)
	if len(list) != 2 {
		t.Fatalf("got %d elements, want 2", len(list))
	}
	if want := 50 * time.Hour; list[0].Timeout != want {
		t.Errorf("timeout = %v, want %v", list[0].Timeout, want)
	}
}

func TestAddElemCopiesTheKey(t *testing.T) {
	t.Parallel()
	env := newTestDaemon(t)
	ip := a("1.2.3.4")
	list := env.addElem(nil, ip, 10)
	copy(ip, a("9.9.9.9"))
	if got := net.IP(list[0].Key).String(); got != "1.2.3.4" {
		t.Errorf("element key = %s, want 1.2.3.4", got)
	}
}

func TestUpdateSendsAddThenReplace(t *testing.T) {
	t.Parallel()
	env := newTestDaemon(t)
	sets := []*nftables.Set{env.conn.sets["v4"], env.conn.sets["v6"]}
	elems := [][]nftables.SetElement{
		{{Key: a("1.2.3.4"), Timeout: time.Hour}},
		{{Key: a6("2001:db8::1"), Timeout: time.Hour}},
	}
	env.update("example.com", sets, elems)

	want := []string{
		"add v4 1.2.3.4=1h0m0s",
		"add v6 2001:db8::1=1h0m0s",
		"flush",
		"del v4 1.2.3.4",
		"add v4 1.2.3.4=1h0m0s",
		"del v6 2001:db8::1",
		"add v6 2001:db8::1=1h0m0s",
		"flush",
	}
	if got := env.conn.ops(); !reflect.DeepEqual(got, want) {
		t.Errorf("calls:\n got %v\nwant %v", got, want)
	}
}

func TestUpdateSkipsEmptySets(t *testing.T) {
	t.Parallel()
	env := newTestDaemon(t)
	sets := []*nftables.Set{env.conn.sets["v4"], env.conn.sets["v6"]}
	elems := [][]nftables.SetElement{{{Key: a("1.2.3.4"), Timeout: time.Hour}}, nil}
	env.update("example.com", sets, elems)
	for _, op := range env.conn.ops() {
		if strings.Contains(op, "v6") {
			t.Errorf("touched the empty set: %s", op)
		}
	}
}

func TestUpdateDryRunOnlyLogs(t *testing.T) {
	t.Parallel()
	env := newTestDaemon(t, func(cfg *config) { cfg.dryRun = true })
	env.update("example.com", []*nftables.Set{env.conn.sets["v4"]},
		[][]nftables.SetElement{{{Key: a("1.2.3.4"), Timeout: time.Hour}}})
	if len(env.conn.calls) != 0 {
		t.Errorf("dry run talked to nftables: %v", env.conn.ops())
	}
	if want := "example.com -> 1.2.3.4 (set v4, 1h0m0s)"; !strings.Contains(env.logged(), want) {
		t.Errorf("log = %q, want it to contain %q", env.logged(), want)
	}
}

func TestUpdateReconnectsAfterFailure(t *testing.T) {
	t.Parallel()
	env := newTestDaemon(t)
	old := env.conn
	old.flushErr = errors.New("kernel said no")
	env.update("example.com", []*nftables.Set{old.sets["v4"]},
		[][]nftables.SetElement{{{Key: a("1.2.3.4"), Timeout: time.Hour}}})

	if env.dialed != 1 {
		t.Errorf("opened %d replacement connections, want 1", env.dialed)
	}
	if env.nft == setConn(old) {
		t.Error("kept the failed connection")
	}
	if got := old.ops(); got[len(got)-1] != "close" {
		t.Errorf("the failed connection was not closed: %v", got)
	}
	if !strings.Contains(env.logged(), "kernel said no") {
		t.Errorf("log = %q, want the failure in it", env.logged())
	}
}

func TestUpdateKeepsConnectionWhenRedialFails(t *testing.T) {
	t.Parallel()
	env := newTestDaemon(t)
	old := env.conn
	old.addErr = errors.New("no such set")
	env.dialErr = errors.New("cannot open netlink socket")
	env.update("example.com", []*nftables.Set{old.sets["v4"]},
		[][]nftables.SetElement{{{Key: a("1.2.3.4"), Timeout: time.Hour}}})

	if env.nft != setConn(old) {
		t.Error("dropped the connection even though no replacement was available")
	}
	if !strings.Contains(env.logged(), "cannot open netlink socket") {
		t.Errorf("log = %q, want the dial error in it", env.logged())
	}
}

func TestOnPacket(t *testing.T) {
	t.Parallel()
	id := uint32(42)
	payload := udp4Reply(reply("example.com", rr{"example.com", typeA, classIN, 300, a("1.2.3.4")}))

	t.Run("accepts and handles the packet", func(t *testing.T) {
		t.Parallel()
		env := newTestDaemon(t)
		var gotID uint32
		var gotVerdict int
		env.verdict = func(id uint32, v int) error { gotID, gotVerdict = id, v; return nil }
		if ret := env.onPacket(nfqueue.Attribute{PacketID: &id, Payload: &payload}); ret != 0 {
			t.Errorf("onPacket = %d, want 0", ret)
		}
		if gotID != id || gotVerdict != nfqueue.NfAccept {
			t.Errorf("verdict(%d, %d), want (%d, accept)", gotID, gotVerdict, id)
		}
		if len(env.conn.calls) == 0 {
			t.Error("the address was not added")
		}
	})

	t.Run("a message without an id is left alone", func(t *testing.T) {
		t.Parallel()
		env := newTestDaemon(t)
		called := false
		env.verdict = func(uint32, int) error { called = true; return nil }
		env.onPacket(nfqueue.Attribute{Payload: &payload})
		if called {
			t.Error("gave a verdict for a packet without an id")
		}
	})

	t.Run("a packet without a payload is still accepted", func(t *testing.T) {
		t.Parallel()
		env := newTestDaemon(t)
		called := false
		env.verdict = func(uint32, int) error { called = true; return nil }
		env.onPacket(nfqueue.Attribute{PacketID: &id})
		if !called {
			t.Error("a packet without a payload was never answered")
		}
	})

	t.Run("a failed verdict is logged", func(t *testing.T) {
		t.Parallel()
		env := newTestDaemon(t)
		env.verdict = func(uint32, int) error { return errors.New("socket closed") }
		env.onPacket(nfqueue.Attribute{PacketID: &id, Payload: &payload})
		if !strings.Contains(env.logged(), "verdict: socket closed") {
			t.Errorf("log = %q, want the verdict error in it", env.logged())
		}
	})
}

func TestOnError(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		err     error
		stopped bool
		want    int
	}{
		{"a read deadline while shutting down", os.ErrDeadlineExceeded, false, 0},
		{"a full kernel buffer", syscall.ENOBUFS, false, 0},
		{"wrapped", errors.Join(errors.New("receive"), syscall.ENOBUFS), false, 0},
		{"anything else once shutdown started", errors.New("broken"), true, 0},
		{"anything else", errors.New("broken"), false, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			env := newTestDaemon(t)
			env.stopped = func() bool { return c.stopped }
			if got := env.onError(c.err); got != c.want {
				t.Fatalf("onError = %d, want %d", got, c.want)
			}
			select {
			case err := <-env.fatal:
				if c.want == 0 {
					t.Errorf("reported %v as fatal", err)
				}
			default:
				if c.want != 0 {
					t.Error("the loop was stopped without reporting why")
				}
			}
		})
	}
}

func TestReloadKeepsDomainsOnError(t *testing.T) {
	t.Parallel()
	env := newTestDaemon(t)
	env.cfg.domFile = "does-not-exist.conf"
	before := env.domains
	env.reload()
	if !reflect.DeepEqual(env.domains, before) {
		t.Error("a failed reload replaced the domain list")
	}
	if !strings.Contains(env.logged(), "reload failed") {
		t.Errorf("log = %q, want a warning", env.logged())
	}
}
