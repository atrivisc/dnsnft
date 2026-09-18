package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/florianl/go-nfqueue/v2"
	"github.com/google/nftables"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

type config struct {
	domFile      string
	def4         string
	def6         string
	extra        time.Duration
	maxTTL       time.Duration
	dryRun       bool
	verbose      bool
	permit       []netip.Prefix
	block        []netip.Prefix
	sameZone     bool
	setSizeLimit int
}

type setConn interface {
	GetSetByName(t *nftables.Table, name string) (*nftables.Set, error)
	SetAddElements(s *nftables.Set, vals []nftables.SetElement) error
	SetDeleteElements(s *nftables.Set, vals []nftables.SetElement) error
	Flush() error
	CloseLasting() error
}

type daemon struct {
	cfg   config
	table *nftables.Table

	mu        sync.Mutex
	nft       setConn
	domains   map[string]*domain
	assembler *reassembly.Assembler

	dial   func() (setConn, error)
	now    func() time.Time
	logger *log.Logger

	verdict func(id uint32, verdict int) error
	stopped func() bool
	fatal   chan error
}

func newDaemon(cfg config, table *nftables.Table) *daemon {
	d := &daemon{
		cfg:     cfg,
		table:   table,
		now:     time.Now,
		logger:  log.Default(),
		dial:    func() (setConn, error) { return nftables.New(nftables.AsLasting()) },
		verdict: func(uint32, int) error { return nil },
		stopped: func() bool { return false },
		fatal:   make(chan error, 1),
	}
	d.assembler = reassembly.NewAssembler(reassembly.NewStreamPool(d))
	d.assembler.MaxBufferedPagesPerConnection = 128
	d.assembler.MaxBufferedPagesTotal = 8192
	return d
}

func (d *daemon) logf(format string, args ...any) { d.logger.Printf(format, args...) }

func (d *daemon) vlog(format string, args ...any) {
	if d.cfg.verbose {
		d.logger.Printf(format, args...)
	}
}

func (d *daemon) onPacket(a nfqueue.Attribute) int {
	if a.PacketID == nil {
		return 0
	}
	d.mu.Lock()
	if a.Payload != nil {
		if err := d.handlePacket(*a.Payload); err != nil {
			d.logf("error handling packet: %v", err)
		}
	}
	d.mu.Unlock()

	if err := d.verdict(*a.PacketID, nfqueue.NfAccept); err != nil {
		d.logf("verdict: %v", err)
	}
	return 0
}

func (d *daemon) onError(err error) int {
	if d.stopped() || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.ENOBUFS) {
		return 0
	}
	d.fatal <- err
	return 1
}

func (d *daemon) handleDNS(msg []byte) {
	var dns layers.DNS
	if err := decodeDNS(&dns, msg); err != nil {
		d.vlog("ignoring a %d byte message: %v", len(msg), err)
		return
	}
	if !dns.QR || dns.OpCode != layers.DNSOpCodeQuery || len(dns.Questions) != 1 ||
		dns.Questions[0].Class != layers.DNSClassIN {
		d.vlog("ignoring a message: response=%v opcode=%v questions=%d", dns.QR, dns.OpCode, len(dns.Questions))
		return
	}

	lower := func(b []byte) string { return strings.ToLower(string(b)) }
	qname := lower(dns.Questions[0].Name)
	if dns.ResponseCode != layers.DNSResponseCodeNoErr {
		d.vlog("%s: answered with %v", qname, dns.ResponseCode)
		return
	}
	dom := d.match(qname)
	if dom == nil {
		d.vlog("%s: no matching domain in %s", qname, d.cfg.domFile)
		return
	}

	if len(dns.Answers) > d.cfg.setSizeLimit {
		d.vlog("%s: answers length over size limit %v", qname, d.cfg.setSizeLimit)
		return
	}

	chain := map[string]bool{qname: true}
	for grew := true; grew; {
		grew = false
		for _, rr := range dns.Answers {
			if rr.Type != layers.DNSTypeCNAME || rr.Class != layers.DNSClassIN {
				continue
			}
			target := lower(rr.CNAME)
			if !chain[lower(rr.Name)] || chain[target] {
				continue
			}
			if d.cfg.sameZone && !under(target, dom.name) {
				d.logf("%q: not following the CNAME to %q, outside %q", qname, target, dom.name)
				continue
			}
			chain[target] = true
			grew = true
		}
	}

	var add4, add6 []nftables.SetElement
	for _, rr := range dns.Answers {
		if rr.Class != layers.DNSClassIN || !chain[lower(rr.Name)] {
			continue
		}

		var v6 bool
		switch {
		case rr.Type == layers.DNSTypeA && len(rr.IP) == 4 && dom.set4 != nil:
		case rr.Type == layers.DNSTypeAAAA && len(rr.IP) == 16 && dom.set6 != nil:
			v6 = true
		default:
			continue
		}

		if p, bad := d.blocked(rr.IP); bad {
			d.logf("%q: refusing %s from %q (%s)", qname, rr.IP, lower(rr.Name), p)
			continue
		}

		if v6 {
			add6 = d.addElem(add6, rr.IP, rr.TTL)
		} else {
			add4 = d.addElem(add4, rr.IP, rr.TTL)
		}
	}

	if len(add4)+len(add6) == 0 {
		d.vlog("%s: no usable address records among %d answers", qname, len(dns.Answers))
		return
	}
	d.update(qname, []*nftables.Set{dom.set4, dom.set6}, [][]nftables.SetElement{add4, add6})
}

func (d *daemon) blocked(ip []byte) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || addr.Is4In6() {
		return netip.Prefix{}, true
	}
	for _, p := range d.cfg.permit {
		if p.Contains(addr) {
			return netip.Prefix{}, false
		}
	}
	for _, p := range d.cfg.block {
		if p.Contains(addr) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

func describe(pkt gopacket.Packet) string {
	src, dst := "?", "?"
	if n := pkt.NetworkLayer(); n != nil {
		src, dst = n.NetworkFlow().Src().String(), n.NetworkFlow().Dst().String()
	}
	t := pkt.TransportLayer()
	if t == nil {
		if e := pkt.ErrorLayer(); e != nil {
			return fmt.Sprintf("%s -> %s, cannot decode: %v", src, dst, e.Error())
		}
		return fmt.Sprintf("%s -> %s, no transport layer", src, dst)
	}
	return fmt.Sprintf("%s:%s -> %s:%s (%s)", src, t.TransportFlow().Src(), dst, t.TransportFlow().Dst(), t.LayerType())
}

func (d *daemon) handlePacket(data []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("malformed DNS message: %v", r)
		}
	}()

	first := layers.LayerTypeIPv4
	if len(data) > 0 && data[0]>>4 == 6 {
		first = layers.LayerTypeIPv6
	}

	pkt := gopacket.NewPacket(data, first, gopacket.DecodeOptions{Lazy: true, NoCopy: false})

	switch l4 := pkt.TransportLayer().(type) {
	case *layers.UDP:
		if l4.SrcPort == 53 {
			d.handleDNS(l4.Payload)
			return
		}
	case *layers.TCP:
		if l4.SrcPort == 53 && !pkt.Metadata().Truncated {
			d.vlog("reassembling %d bytes of a TCP stream: %s", len(l4.Payload), describe(pkt))
			netLayer := pkt.NetworkLayer()
			if netLayer == nil {
				return fmt.Errorf("failed to get NetworkLayer of packet: %s", describe(pkt))
			}
			flow := netLayer.NetworkFlow()
			d.assembler.AssembleWithContext(flow, l4, captureTime(d.now()))
			return
		}
	}
	return fmt.Errorf("ignoring a queued packet: %s", describe(pkt))
}

func (d *daemon) flush() {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()

	d.assembler.FlushWithOptions(reassembly.FlushOptions{T: now.Add(-30 * time.Second), TC: now.Add(-5 * time.Minute)})
}

func (d *daemon) reload() {
	d.mu.Lock()
	defer d.mu.Unlock()
	domains, err := d.loadDomains(d.cfg.domFile)
	if err != nil {
		d.logf("reload failed, keeping %d domains: %v", len(d.domains), err)
		return
	}
	d.domains = domains
	d.logf("loaded %d domains", len(domains))
}

func (d *daemon) reconnect() {
	c, err := d.dial()
	if err != nil {
		d.logf("reconnecting to nftables: %v", err)
		return
	}

	_ = d.nft.CloseLasting()
	d.nft = c
}

func (d *daemon) update(qname string, sets []*nftables.Set, elems [][]nftables.SetElement) {
	if d.cfg.verbose || d.cfg.dryRun {
		for i, set := range sets {
			for _, e := range elems[i] {
				d.logf("%s -> %s (set %s, %s)", qname, net.IP(e.Key), set.Name, e.Timeout)
			}
		}
	}

	if d.cfg.dryRun {
		return
	}

	queue := func(replace bool) error {
		for i, set := range sets {
			if len(elems[i]) == 0 {
				continue
			}

			if replace {
				keys := make([]nftables.SetElement, len(elems[i]))
				for j, e := range elems[i] {
					keys[j].Key = e.Key
				}

				if err := d.nft.SetDeleteElements(set, keys); err != nil {
					return err
				}
			}

			if err := d.nft.SetAddElements(set, elems[i]); err != nil {
				return err
			}

		}
		return d.nft.Flush()
	}

	err := queue(false)
	if err == nil {
		err = queue(true)
	}

	if err != nil {
		d.logf("updating sets for %s: %v", qname, err)
		d.reconnect()
	}
}

func (d *daemon) addElem(list []nftables.SetElement, ip []byte, ttl uint32) []nftables.SetElement {
	if ttl > math.MaxInt32 {
		ttl = 0
	}

	timeout := min(time.Duration(ttl)*time.Second, d.cfg.maxTTL)
	timeout = max((timeout + d.cfg.extra).Truncate(time.Second), time.Second)

	for i := range list {
		if bytes.Equal(list[i].Key, ip) {
			if timeout > list[i].Timeout {
				list[i].Timeout = timeout
			}
			return list
		}
	}

	return append(list, nftables.SetElement{Key: append([]byte(nil), ip...), Timeout: timeout})
}
