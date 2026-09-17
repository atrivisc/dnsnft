package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket/reassembly"
)

func (f *fakeConn) added() []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range f.calls {
		if c.op != "add" {
			continue
		}
		for _, e := range c.elems {
			if s := c.set + " " + net.IP(e.Key).String(); !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func TestHandleDNS(t *testing.T) {
	t.Parallel()
	ip4 := rr{"example.com", typeA, classIN, 300, a("93.184.216.34")}
	for _, c := range []struct {
		name string
		msg  []byte
		want []string
		log  string
	}{{
		name: "an address for a listed name",
		msg:  reply("example.com", ip4),
		want: []string{"v4 93.184.216.34"},
	}, {
		name: "a subdomain of a wildcard entry, mixed case and a compressed owner name",
		msg:  reply("WWW.Example.COM", rr{"@q", typeAAAA, classIN, 300, a6("2606:2800::1")}),
		want: []string{"v6 2606:2800::1"},
	}, {
		name: "both families at once",
		msg: reply("example.com", ip4,
			rr{"example.com", typeAAAA, classIN, 300, a6("2606:2800::1")}),
		want: []string{"v4 93.184.216.34", "v6 2606:2800::1"},
	}, {
		name: "a name that is not listed",
		msg:  reply("notlisted.org", rr{"notlisted.org", typeA, classIN, 300, a("1.1.1.1")}),
		log:  "no matching domain",
	}, {
		name: "a subdomain of an exact entry",
		msg:  reply("sub.exact.example", rr{"@q", typeA, classIN, 300, a("1.1.1.1")}),
		log:  "no matching domain",
	}, {
		name: "a name that only looks like a listed one",
		msg:  reply("example.com.evil.net", rr{"@q", typeA, classIN, 300, a("1.1.1.1")}),
		log:  "no matching domain",
	}, {
		name: "an error response",
		msg:  dnsMsg(flagsNXDomain, 1, "example.com", ip4),
		log:  "answered with",
	}, {
		name: "a query rather than a response",
		msg:  dnsMsg(flagsQuery, 1, "example.com", ip4),
		log:  "ignoring a message",
	}, {
		name: "another opcode",
		msg:  dnsMsg(flagsStatus, 1, "example.com", ip4),
		log:  "ignoring a message",
	}, {
		name: "more than one question",
		msg:  dnsMsg(flagsResponse, 2, "example.com", ip4),
		log:  "ignoring a message",
	}, {
		name: "a chain of CNAMEs ending in addresses",
		msg: reply("example.com",
			rr{"example.com", typeCNAME, classIN, 300, wireName("edge.provider.net")},
			rr{"edge.provider.net", typeCNAME, classIN, 300, wireName("EDGE2.provider.net")},
			rr{"edge2.provider.net", typeA, classIN, 300, a("198.51.100.1")},
			rr{"unrelated.org", typeA, classIN, 300, a("203.0.113.9")}),
		want: []string{"v4 198.51.100.1"},
	}, {
		name: "records that belong to no name in the chain",
		msg:  reply("example.com", rr{"unrelated.org", typeA, classIN, 300, a("203.0.113.9")}),
		log:  "no usable address records",
	}, {
		name: "an address record of the wrong length",
		msg:  reply("example.com", rr{"example.com", typeA, classIN, 300, []byte{1, 2, 3, 4, 5}}),
		log:  "no usable address records",
	}, {
		name: "a record in another class",
		msg:  reply("example.com", rr{"example.com", typeA, classCH, 300, a("1.1.1.1")}),
		log:  "no usable address records",
	}, {
		name: "an IPv6 address for an entry without a v6 set",
		msg:  reply("v4only.test", rr{"@q", typeAAAA, classIN, 300, a6("2606:2800::1")}),
		log:  "no usable address records",
	}, {
		name: "a truncated message",
		msg:  reply("example.com", ip4)[:20],
		log:  "ignoring a 20 byte message",
	}, {
		name: "an empty message",
		msg:  nil,
		log:  "ignoring a 0 byte message",
	}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			env := newTestDaemon(t)
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

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestHandlePacket(t *testing.T) {
	t.Parallel()
	msg := reply("example.com", rr{"example.com", typeA, classIN, 300, a("93.184.216.34")})
	for _, c := range []struct {
		name string
		pkt  []byte
		want []string
		log  string
	}{
		{"a UDP reply over IPv4", udp4Reply(msg), []string{"v4 93.184.216.34"}, ""},
		{"a UDP reply over IPv6", udp6Reply(msg), []string{"v4 93.184.216.34"}, ""},
		{"UDP from another port", ipv4(17, udp(5353, msg)), nil, "ignoring a queued packet"},
		{"a TCP segment goes to the reassembler", ipv4(6, tcp(50000, 1000, synAck, nil)), nil, "reassembling"},
		{"something that is not IP", []byte{0x33, 0x44, 0x55}, nil, "ignoring a queued packet"},
		{"nothing at all", nil, nil, "ignoring a queued packet"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			env := newTestDaemon(t)
			env.handlePacket(c.pkt)
			if got := env.conn.added(); !equal(got, c.want) {
				t.Errorf("added %v, want %v", got, c.want)
			}
			if c.log != "" && !strings.Contains(env.logged(), c.log) {
				t.Errorf("log = %q, want it to mention %q", env.logged(), c.log)
			}
		})
	}
}

func TestTCPStream(t *testing.T) {
	t.Parallel()
	one := framed(reply("example.com", rr{"example.com", typeA, classIN, 300, a("198.51.100.1")}))
	two := framed(reply("www.example.com", rr{"@q", typeA, classIN, 300, a("198.51.100.2")}))
	stream := append(append([]byte{}, one...), two...)
	const isn = 1000

	t.Run("messages split across segments", func(t *testing.T) {
		t.Parallel()
		env := newTestDaemon(t)
		env.handlePacket(ipv4(6, tcp(50001, isn, synAck, nil)))
		prev := 0
		for _, cut := range []int{1, 5, len(one) + 3, len(stream)} {
			env.handlePacket(ipv4(6, tcp(50001, uint32(isn+1+prev), pshAck, stream[prev:cut])))
			prev = cut
		}
		env.handlePacket(ipv4(6, tcp(50001, uint32(isn+1+len(stream)), finAck, nil)))
		want := []string{"v4 198.51.100.1", "v4 198.51.100.2"}
		if got := env.conn.added(); !equal(got, want) {
			t.Errorf("added %v, want %v", got, want)
		}
	})

	t.Run("segments arriving out of order", func(t *testing.T) {
		t.Parallel()
		env := newTestDaemon(t)
		env.handlePacket(ipv4(6, tcp(50002, isn, synAck, nil)))
		cuts := []int{0, 7, len(one), len(stream)}
		for i := len(cuts) - 2; i >= 0; i-- {
			env.handlePacket(ipv4(6, tcp(50002, uint32(isn+1+cuts[i]), pshAck, stream[cuts[i]:cuts[i+1]])))
		}
		want := []string{"v4 198.51.100.1", "v4 198.51.100.2"}
		if got := env.conn.added(); !equal(got, want) {
			t.Errorf("added %v, want %v", got, want)
		}
	})

	t.Run("a connection whose handshake was not seen is ignored", func(t *testing.T) {
		t.Parallel()
		env := newTestDaemon(t)
		env.handlePacket(ipv4(6, tcp(50003, isn+1, pshAck, stream)))
		if got := env.conn.added(); len(got) != 0 {
			t.Errorf("added %v from a stream of unknown offset", got)
		}
	})

	t.Run("a gap makes the daemon give up on the stream", func(t *testing.T) {
		t.Parallel()
		env := newTestDaemon(t)
		env.handlePacket(ipv4(6, tcp(50004, isn, synAck, nil)))
		env.handlePacket(ipv4(6, tcp(50004, uint32(isn+1+len(one)), pshAck, stream[len(one):])))

		later := env.now().Add(time.Hour)
		env.assembler.FlushWithOptions(reassembly.FlushOptions{T: later, TC: later})
		if !strings.Contains(env.logged(), "dropping a TCP stream") {
			t.Errorf("log = %q, want the dropped stream in it", env.logged())
		}
		env.handlePacket(ipv4(6, tcp(50004, uint32(isn+1), pshAck, one)))
		if got := env.conn.added(); len(got) != 0 {
			t.Errorf("added %v after the stream was broken", got)
		}
	})

	t.Run("flush only reaches connections older than its window", func(t *testing.T) {
		t.Parallel()
		env := newTestDaemon(t)
		env.handlePacket(ipv4(6, tcp(50005, isn, synAck, nil)))
		env.handlePacket(ipv4(6, tcp(50005, uint32(isn+1+len(one)), pshAck, stream[len(one):])))
		env.flush()
		if strings.Contains(env.logged(), "dropping a TCP stream") {
			t.Error("flush dropped a stream that had just arrived")
		}
	})
}
