package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
)

type call struct {
	op    string
	set   string
	elems []nftables.SetElement
}

type fakeConn struct {
	sets  map[string]*nftables.Set
	calls []call

	getErr, addErr, delErr, flushErr error
}

func newFakeConn(sets ...*nftables.Set) *fakeConn {
	f := &fakeConn{sets: map[string]*nftables.Set{}}
	for _, s := range sets {
		f.sets[s.Name] = s
	}
	return f
}

func v4set(name string) *nftables.Set {
	return &nftables.Set{Name: name, KeyType: nftables.TypeIPAddr, HasTimeout: true}
}

func v6set(name string) *nftables.Set {
	return &nftables.Set{Name: name, KeyType: nftables.TypeIP6Addr, HasTimeout: true}
}

func (f *fakeConn) GetSetByName(_ *nftables.Table, name string) (*nftables.Set, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	s, ok := f.sets[name]
	if !ok {
		return nil, errNoSet
	}
	return s, nil
}

func (f *fakeConn) SetAddElements(s *nftables.Set, vals []nftables.SetElement) error {
	f.calls = append(f.calls, call{op: "add", set: s.Name, elems: vals})
	return f.addErr
}

func (f *fakeConn) SetDeleteElements(s *nftables.Set, vals []nftables.SetElement) error {
	f.calls = append(f.calls, call{op: "del", set: s.Name, elems: vals})
	return f.delErr
}

func (f *fakeConn) Flush() error {
	f.calls = append(f.calls, call{op: "flush"})
	return f.flushErr
}

func (f *fakeConn) CloseLasting() error {
	f.calls = append(f.calls, call{op: "close"})
	return nil
}

func (f *fakeConn) ops() []string {
	var out []string
	for _, c := range f.calls {
		if c.op == "flush" || c.op == "close" {
			out = append(out, c.op)
			continue
		}
		var parts []string
		for _, e := range c.elems {
			s := net.IP(e.Key).String()
			if c.op == "add" {
				s += "=" + e.Timeout.String()
			}
			parts = append(parts, s)
		}
		out = append(out, c.op+" "+c.set+" "+strings.Join(parts, ","))
	}
	return out
}

var errNoSet = errorString("no such set")

type errorString string

func (e errorString) Error() string { return string(e) }

type testEnv struct {
	*daemon
	conn *fakeConn
	logs *bytes.Buffer
	dialed  int
	dialErr error
}

func newTestDaemon(t testing.TB, opts ...func(*config)) *testEnv {
	t.Helper()
	cfg := config{domFile: "domains.conf", extra: 48 * time.Hour, maxTTL: 24 * time.Hour, verbose: true}
	for _, o := range opts {
		o(&cfg)
	}
	env := &testEnv{conn: newFakeConn(v4set("v4"), v6set("v6")), logs: &bytes.Buffer{}}
	env.daemon = newDaemon(cfg, &nftables.Table{Name: "filter", Family: nftables.TableFamilyINet})
	env.logger = log.New(env.logs, "", 0)
	env.nft = env.conn
	env.now = func() time.Time { return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC) }
	env.dial = func() (setConn, error) {
		env.dialed++
		if env.dialErr != nil {
			return nil, env.dialErr
		}
		return newFakeConn(), nil
	}
	env.domains = map[string]*domain{
		"example.com":   {set4: env.conn.sets["v4"], set6: env.conn.sets["v6"], wildcard: true},
		"v4only.test":   {set4: env.conn.sets["v4"]},
		"exact.example": {set4: env.conn.sets["v4"], set6: env.conn.sets["v6"]},
	}
	return env
}

func (e *testEnv) logged() string { return e.logs.String() }

const (
	typeA     = 1
	typeCNAME = 5
	typeAAAA  = 28
	classIN   = 1
	classCH   = 3

	flagsResponse = 0x8180
	flagsQuery    = 0x0100
	flagsNXDomain = 0x8183
	flagsStatus   = 0x9180
)

type rr struct {
	name  string
	typ   uint16
	class uint16
	ttl   uint32
	data  []byte
}

func wireName(n string) []byte {
	if n == "@q" {
		return []byte{0xc0, 0x0c}
	}
	var b []byte
	for _, l := range strings.Split(n, ".") {
		if l != "" {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
	}
	return append(b, 0)
}

func dnsMsg(flags uint16, qdcount int, qname string, answers ...rr) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], 0x1234)
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[4:], uint16(qdcount))
	binary.BigEndian.PutUint16(b[6:], uint16(len(answers)))
	for range qdcount {
		b = append(b, wireName(qname)...)
		b = append(b, 0, 1, 0, 1)
	}
	for _, a := range answers {
		b = append(b, wireName(a.name)...)
		h := make([]byte, 10)
		binary.BigEndian.PutUint16(h[0:], a.typ)
		binary.BigEndian.PutUint16(h[2:], a.class)
		binary.BigEndian.PutUint32(h[4:], a.ttl)
		binary.BigEndian.PutUint16(h[8:], uint16(len(a.data)))
		b = append(b, h...)
		b = append(b, a.data...)
	}
	return b
}

func reply(qname string, answers ...rr) []byte {
	return dnsMsg(flagsResponse, 1, qname, answers...)
}

func a(ip string) []byte  { return net.ParseIP(ip).To4() }
func a6(ip string) []byte { return net.ParseIP(ip).To16() }

var (
	srv4 = net.IPv4(192, 0, 2, 53).To4()
	cli4 = net.IPv4(192, 0, 2, 10).To4()
	srv6 = net.ParseIP("2001:db8::53")
	cli6 = net.ParseIP("2001:db8::10")
)

func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func ipv4(proto byte, l4 []byte) []byte {
	h := make([]byte, 20, 20+len(l4))
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(l4)))
	binary.BigEndian.PutUint16(h[6:], 0x4000)
	h[8], h[9] = 64, proto
	copy(h[12:], srv4)
	copy(h[16:], cli4)
	binary.BigEndian.PutUint16(h[10:], checksum(h))
	return append(h, l4...)
}

func ipv6(proto byte, l4 []byte) []byte {
	h := make([]byte, 40, 40+len(l4))
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(l4)))
	h[6], h[7] = proto, 64
	copy(h[8:], srv6)
	copy(h[24:], cli6)
	return append(h, l4...)
}

func udp(sport uint16, payload []byte) []byte {
	h := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], 40000)
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
	return append(h, payload...)
}

const (
	synAck = 0x12
	pshAck = 0x18
	finAck = 0x11
)

func tcp(dport uint16, seq uint32, flags byte, payload []byte) []byte {
	h := make([]byte, 20, 20+len(payload))
	binary.BigEndian.PutUint16(h[0:], 53)
	binary.BigEndian.PutUint16(h[2:], dport)
	binary.BigEndian.PutUint32(h[4:], seq)
	binary.BigEndian.PutUint32(h[8:], 1)
	h[12], h[13] = 5<<4, flags
	binary.BigEndian.PutUint16(h[14:], 65535)
	return append(h, payload...)
}

func framed(msg []byte) []byte {
	return append([]byte{byte(len(msg) >> 8), byte(len(msg))}, msg...)
}

func udp4Reply(msg []byte) []byte { return ipv4(17, udp(53, msg)) }
func udp6Reply(msg []byte) []byte { return ipv6(17, udp(53, msg)) }
