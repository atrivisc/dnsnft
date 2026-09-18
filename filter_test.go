package main

import (
	"flag"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func withBlock(s string) func(*config) {
	return func(cfg *config) { cfg.block = mustPrefixes(s) }
}

func withPermit(s string) func(*config) {
	return func(cfg *config) { cfg.permit = mustPrefixes(s) }
}

func withSameZone(on bool) func(*config) {
	return func(cfg *config) { cfg.sameZone = on }
}

func TestPrefixListSet(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		args []string
		want string
		err  string
	}{{
		name: "a single prefix",
		args: []string{"10.0.0.0/8"},
		want: "10.0.0.0/8",
	}, {
		name: "a comma separated list",
		args: []string{"10.0.0.0/8,192.168.0.0/16"},
		want: "10.0.0.0/8,192.168.0.0/16",
	}, {
		name: "the flag repeated",
		args: []string{"10.0.0.0/8", "fc00::/7"},
		want: "10.0.0.0/8,fc00::/7",
	}, {
		name: "surrounding and empty fields",
		args: []string{" 10.0.0.0/8 , ,192.168.0.0/16,"},
		want: "10.0.0.0/8,192.168.0.0/16",
	}, {
		name: "host bits are masked off",
		args: []string{"10.1.2.3/8,2001:db8:1234::5/32"},
		want: "10.0.0.0/8,2001:db8::/32",
	}, {
		name: "a single address",
		args: []string{"169.254.169.254/32"},
		want: "169.254.169.254/32",
	}, {
		name: "an empty string",
		args: []string{""},
		want: "",
	}, {
		name: "a v4 mapped prefix",
		args: []string{"::ffff:10.0.0.0/104"},
		err:  "dotted-quad",
	}, {
		name: "a bare address",
		args: []string{"10.0.0.0"},
		err:  "10.0.0.0",
	}, {
		name: "a prefix length out of range",
		args: []string{"10.0.0.0/33"},
		err:  "10.0.0.0/33",
	}, {
		name: "nonsense",
		args: []string{"not a cidr"},
		err:  "not a cidr",
	}, {
		name: "a good prefix after a bad one",
		args: []string{"10.0.0.0/8", "garbage"},
		err:  "garbage",
	}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var p prefixList
			var err error
			for _, a := range c.args {
				if err = p.Set(a); err != nil {
					break
				}
			}

			switch {
			case c.err != "" && err == nil:
				t.Fatalf("Set(%q) = nil, want an error mentioning %q", c.args, c.err)
			case c.err != "" && !strings.Contains(err.Error(), c.err):
				t.Fatalf("Set(%q) = %v, want it to mention %q", c.args, err, c.err)
			case c.err == "" && err != nil:
				t.Fatalf("Set(%q) = %v, want no error", c.args, err)
			case c.err != "":
				return
			}

			if got := p.String(); got != c.want {
				t.Errorf("String() = %q, want %q", got, c.want)
			}
			if !p.set {
				t.Error("set = false, want the flag to record that it was given")
			}
		})
	}
}

func TestPrefixListRecordsAnEmptyFlag(t *testing.T) {
	t.Parallel()
	var p prefixList
	if p.set {
		t.Error("set = true before the flag was given")
	}
	if err := p.Set(""); err != nil {
		t.Fatal(err)
	}
	if !p.set || len(p.ps) != 0 {
		t.Errorf("set = %v, prefixes = %v; want -X '' to disable blocking rather than fall back to the bogons",
			p.set, p.ps)
	}
}

func TestBlocked(t *testing.T) {
	t.Parallel()
	const private = "10.0.0.0/8,192.168.0.0/16,fc00::/7"
	for _, c := range []struct {
		name   string
		block  string
		permit string
		ip     []byte
		want   bool
	}{{
		name: "nothing is blocked when no prefixes are given",
		ip:   a("10.0.0.1"),
	}, {
		name:  "a v4 address inside a blocked prefix",
		block: private,
		ip:    a("10.1.2.3"),
		want:  true,
	}, {
		name:  "a v4 address outside every blocked prefix",
		block: private,
		ip:    a("93.184.216.34"),
	}, {
		name:  "a v6 address inside a blocked prefix",
		block: private,
		ip:    a6("fd00::1"),
		want:  true,
	}, {
		name:  "a v6 address outside every blocked prefix",
		block: private,
		ip:    a6("2606:2800::1"),
	}, {
		name:  "a v4 prefix does not catch a v6 address",
		block: "10.0.0.0/8",
		ip:    a6("2606:2800::1"),
	}, {
		name:   "a permitted subnet inside a blocked one",
		block:  private,
		permit: "10.42.0.0/16",
		ip:     a("10.42.0.7"),
	}, {
		name:   "an address in the blocked range but outside the permitted subnet",
		block:  private,
		permit: "10.42.0.0/16",
		ip:     a("10.43.0.7"),
		want:   true,
	}, {
		name:   "permitting beats blocking on the same prefix",
		block:  "10.0.0.0/8",
		permit: "10.0.0.0/8",
		ip:     a("10.1.2.3"),
	}, {
		name:   "permitting a v6 subnet inside a blocked one",
		block:  private,
		permit: "fd00:42::/32",
		ip:     a6("fd00:42::1"),
	}, {
		name: "a v4 mapped address in a AAAA record",
		ip:   net.ParseIP("127.0.0.1").To16(),
		want: true,
	}, {
		name:   "a v4 mapped address even when the v4 form is permitted",
		block:  private,
		permit: "0.0.0.0/0,::/0",
		ip:     net.ParseIP("10.0.0.1").To16(),
		want:   true,
	}, {
		name: "a slice that is not an address at all",
		ip:   []byte{1, 2, 3, 4, 5},
		want: true,
	}, {
		name: "an empty slice",
		ip:   nil,
		want: true,
	}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			env := newTestDaemon(t, withBlock(c.block), withPermit(c.permit))
			p, got := env.blocked(c.ip)
			if got != c.want {
				t.Fatalf("blocked(%s) = %v, want %v", net.IP(c.ip), got, c.want)
			}
			if got && c.ip != nil && len(c.ip) == 4 && p == (netip.Prefix{}) && c.block != "" {
				t.Errorf("blocked(%s) returned no prefix, want the one that matched", net.IP(c.ip))
			}
		})
	}
}

func TestDefaultBogons(t *testing.T) {
	t.Parallel()
	env := newTestDaemon(t, func(cfg *config) { cfg.block = bogons })
	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"0.0.0.0", true},
		{"10.0.0.1", true},
		{"100.64.0.1", true},
		{"127.0.0.1", true},
		{"169.254.169.254", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"224.0.0.1", true},
		{"255.255.255.255", true},
		{"93.184.216.34", false},
		{"8.8.8.8", false},
		{"::", true},
		{"::1", true},
		{"fc00::1", true},
		{"fd00::1", true},
		{"fe80::1", true},
		{"ff02::1", true},
		{"2606:2800::1", false},
	} {
		ip := net.ParseIP(c.ip)
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
		if _, got := env.blocked(ip); got != c.want {
			t.Errorf("blocked(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestHandleDNSBlocksAddresses(t *testing.T) {
	t.Parallel()
	const private = "10.0.0.0/8,169.254.0.0/16,fc00::/7"
	for _, c := range []struct {
		name   string
		block  string
		permit string
		msg    []byte
		want   []string
		log    string
	}{{
		name:  "a blocked address is refused",
		block: private,
		msg:   reply("example.com", rr{"example.com", typeA, classIN, 300, a("169.254.169.254")}),
		log:   "refusing 169.254.169.254",
	}, {
		name:  "the rest of the answer survives one blocked address",
		block: private,
		msg: reply("example.com",
			rr{"example.com", typeA, classIN, 300, a("10.0.0.1")},
			rr{"example.com", typeA, classIN, 300, a("93.184.216.34")}),
		want: []string{"v4 93.184.216.34"},
		log:  "refusing 10.0.0.1",
	}, {
		name:  "a blocked address reached through a CNAME",
		block: private,
		msg: reply("example.com",
			rr{"example.com", typeCNAME, classIN, 300, wireName("edge.example.com")},
			rr{"edge.example.com", typeA, classIN, 300, a("10.0.0.1")}),
		log: "refusing 10.0.0.1 from \"edge.example.com\"",
	}, {
		name:  "a blocked v6 address",
		block: private,
		msg:   reply("example.com", rr{"example.com", typeAAAA, classIN, 300, a6("fd00::1")}),
		log:   "refusing fd00::1",
	}, {
		name:  "a v4 mapped address in a AAAA record",
		block: private,
		msg:   reply("example.com", rr{"example.com", typeAAAA, classIN, 300, net.ParseIP("10.0.0.1").To16()}),
		log:   "refusing",
	}, {
		name:   "a permitted address inside a blocked range",
		block:  private,
		permit: "10.42.0.0/16",
		msg:    reply("example.com", rr{"example.com", typeA, classIN, 300, a("10.42.0.7")}),
		want:   []string{"v4 10.42.0.7"},
	}, {
		name: "no blocking configured",
		msg:  reply("example.com", rr{"example.com", typeA, classIN, 300, a("10.0.0.1")}),
		want: []string{"v4 10.0.0.1"},
	}, {
		name:  "an answer with nothing left after blocking",
		block: private,
		msg: reply("example.com",
			rr{"example.com", typeA, classIN, 300, a("10.0.0.1")},
			rr{"example.com", typeAAAA, classIN, 300, a6("fd00::1")}),
		log: "no usable address records",
	}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			env := newTestDaemon(t, withBlock(c.block), withPermit(c.permit))
			env.handleDNS(c.msg)
			if got := env.conn.added(); !equal(got, c.want) {
				t.Errorf("added %v, want %v", got, c.want)
			}
			if c.log != "" && !strings.Contains(env.logged(), c.log) {
				t.Errorf("log = %q, want it to mention %q", env.logged(), c.log)
			}
		})
	}
}

func TestBlockingIsLoggedWithoutVerbose(t *testing.T) {
	t.Parallel()
	env := newTestDaemon(t, withBlock("10.0.0.0/8"), func(cfg *config) { cfg.verbose = false })
	env.handleDNS(reply("example.com", rr{"example.com", typeA, classIN, 300, a("10.0.0.1")}))
	if !strings.Contains(env.logged(), "refusing 10.0.0.1") {
		t.Errorf("log = %q, want a refused address reported even when -v is off", env.logged())
	}
}

func TestUnder(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, zone string
		want       bool
	}{
		{"example.com", "example.com", true},
		{"www.example.com", "example.com", true},
		{"a.b.c.example.com", "example.com", true},
		{"notexample.com", "example.com", false},
		{"badexample.com", "example.com", false},
		{"example.com.evil.net", "example.com", false},
		{"example.com", "www.example.com", false},
		{"edge.provider.net", "example.com", false},
		{"", "example.com", false},
		{"example.com", "", false},
	} {
		if got := under(c.name, c.zone); got != c.want {
			t.Errorf("under(%q, %q) = %v, want %v", c.name, c.zone, got, c.want)
		}
	}
}

func TestSameZoneCNAMEs(t *testing.T) {
	t.Parallel()
	crossZone := []rr{
		{"www.example.com", typeCNAME, classIN, 300, wireName("edge.provider.net")},
		{"edge.provider.net", typeA, classIN, 300, a("93.184.216.34")},
	}
	inZone := []rr{
		{"www.example.com", typeCNAME, classIN, 300, wireName("edge.example.com")},
		{"edge.example.com", typeA, classIN, 300, a("93.184.216.34")},
	}

	for _, c := range []struct {
		name     string
		sameZone bool
		qname    string
		answers  []rr
		want     []string
		log      string
	}{{
		name:    "a cross zone CNAME is followed when the check is off",
		qname:   "www.example.com",
		answers: crossZone,
		want:    []string{"v4 93.184.216.34"},
	}, {
		name:     "a cross zone CNAME is refused",
		sameZone: true,
		qname:    "www.example.com",
		answers:  crossZone,
		log:      "not following the CNAME to \"edge.provider.net\", outside \"example.com\"",
	}, {
		name:     "an in zone CNAME is still followed",
		sameZone: true,
		qname:    "www.example.com",
		answers:  inZone,
		want:     []string{"v4 93.184.216.34"},
	}, {
		name:     "an address at the matched name needs no CNAME",
		sameZone: true,
		qname:    "www.example.com",
		answers:  []rr{{"www.example.com", typeA, classIN, 300, a("93.184.216.34")}},
		want:     []string{"v4 93.184.216.34"},
	}, {
		name:     "a chain is cut where it leaves the zone",
		sameZone: true,
		qname:    "www.example.com",
		answers: []rr{
			{"www.example.com", typeCNAME, classIN, 300, wireName("edge.example.com")},
			{"edge.example.com", typeA, classIN, 300, a("93.184.216.34")},
			{"edge.example.com", typeCNAME, classIN, 300, wireName("far.provider.net")},
			{"far.provider.net", typeA, classIN, 300, a("203.0.113.9")},
		},
		want: []string{"v4 93.184.216.34"},
		log:  "not following the CNAME to \"far.provider.net\"",
	}, {
		name:     "the zone of a wildcard entry is the listed name",
		sameZone: true,
		qname:    "deep.sub.example.com",
		answers: []rr{
			{"deep.sub.example.com", typeCNAME, classIN, 300, wireName("other.example.com")},
			{"other.example.com", typeA, classIN, 300, a("93.184.216.34")},
		},
		want: []string{"v4 93.184.216.34"},
	}, {
		name:     "a target that only looks like it is in the zone",
		sameZone: true,
		qname:    "www.example.com",
		answers: []rr{
			{"www.example.com", typeCNAME, classIN, 300, wireName("evilexample.com")},
			{"evilexample.com", typeA, classIN, 300, a("203.0.113.9")},
		},
		log: "not following the CNAME to \"evilexample.com\"",
	}, {
		name:     "a target that appends the zone to another name",
		sameZone: true,
		qname:    "www.example.com",
		answers: []rr{
			{"www.example.com", typeCNAME, classIN, 300, wireName("example.com.evil.net")},
			{"example.com.evil.net", typeA, classIN, 300, a("203.0.113.9")},
		},
		log: "not following the CNAME to \"example.com.evil.net\"",
	}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			env, err := loadList(t, "*.example.com\n", withSameZone(c.sameZone))
			if err != nil {
				t.Fatal(err)
			}
			env.handleDNS(reply(c.qname, c.answers...))
			if got := env.conn.added(); !equal(got, c.want) {
				t.Errorf("added %v, want %v", got, c.want)
			}
			if c.log != "" && !strings.Contains(env.logged(), c.log) {
				t.Errorf("log = %q, want it to mention %q", env.logged(), c.log)
			}
		})
	}
}

func TestSameZoneUsesTheListedNameNotTheQuestion(t *testing.T) {
	t.Parallel()
	env, err := loadList(t, "*.example.com\n", withSameZone(true))
	if err != nil {
		t.Fatal(err)
	}
	env.handleDNS(reply("a.b.example.com",
		rr{"a.b.example.com", typeCNAME, classIN, 300, wireName("c.example.com")},
		rr{"c.example.com", typeA, classIN, 300, a("93.184.216.34")}))

	if got := env.conn.added(); !equal(got, []string{"v4 93.184.216.34"}) {
		t.Errorf("added %v, want the sibling name to be followed because the zone is example.com", got)
	}
}

func TestFlagDefaults(t *testing.T) {
	t.Parallel()
	f := flag.Lookup("C")
	if f == nil {
		t.Fatal("no -C flag is registered")
	}
	if f.DefValue != "true" {
		t.Errorf("-C defaults to %q, want \"true\"", f.DefValue)
	}

	var p prefixList
	if p.set {
		t.Fatal("an unset prefix list reports that the flag was given")
	}
	if len(bogons) == 0 {
		t.Error("the default block list is empty")
	}
}
