package main

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

type daemon struct {
	mu        sync.Mutex
	nft       *nftables.Conn
	table     *nftables.Table
	domains   map[string]*domain
	assembler *reassembly.Assembler
}

func (d *daemon) handleDNS(msg []byte) {
	var dns layers.DNS
	if err := decodeDNS(&dns, msg); err != nil {
		vlog("ignoring a %d byte message: %v", len(msg), err)
		return
	}

	if !dns.QR || dns.OpCode != layers.DNSOpCodeQuery || len(dns.Questions) != 1 ||
		dns.Questions[0].Class != layers.DNSClassIN {
		vlog("ignoring a message: response=%v opcode=%v questions=%d", dns.QR, dns.OpCode, len(dns.Questions))
		return
	}

	lower := func(b []byte) string { return strings.ToLower(string(b)) }
	qname := lower(dns.Questions[0].Name)
	if dns.ResponseCode != layers.DNSResponseCodeNoErr {
		vlog("%s: answered with %v", qname, dns.ResponseCode)
		return
	}

	dom := d.match(qname)
	if dom == nil {
		vlog("%s: no matching domain in %s", qname, *domFile)
		return
	}

	chain := map[string]bool{qname: true}
	for grew := true; grew && len(chain) < 16; {
		grew = false
		for _, rr := range dns.Answers {
			if rr.Type == layers.DNSTypeCNAME && rr.Class == layers.DNSClassIN &&
				chain[lower(rr.Name)] && !chain[lower(rr.CNAME)] {
				chain[lower(rr.CNAME)] = true
				grew = true
			}
		}
	}

	var add4, add6 []nftables.SetElement
	for _, rr := range dns.Answers {
		if rr.Class != layers.DNSClassIN || !chain[lower(rr.Name)] {
			continue
		}
		switch {
		case rr.Type == layers.DNSTypeA && len(rr.IP) == 4 && dom.set4 != nil:
			add4 = addElem(add4, rr.IP, rr.TTL)
		case rr.Type == layers.DNSTypeAAAA && len(rr.IP) == 16 && dom.set6 != nil:
			add6 = addElem(add6, rr.IP, rr.TTL)
		}
	}

	if len(add4)+len(add6) == 0 {
		vlog("%s: no usable address records among %d answers", qname, len(dns.Answers))
		return
	}
	d.update(qname, []*nftables.Set{dom.set4, dom.set6}, [][]nftables.SetElement{add4, add6})
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

func (d *daemon) handlePacket(data []byte) {
	first := layers.LayerTypeIPv4
	if len(data) > 0 && data[0]>>4 == 6 {
		first = layers.LayerTypeIPv6
	}

	pkt := gopacket.NewPacket(data, first, gopacket.DecodeOptions{Lazy: true, NoCopy: true})

	switch l4 := pkt.TransportLayer().(type) {
        case *layers.UDP:
            if l4.SrcPort == 53 {
                d.handleDNS(l4.Payload)
                return
            }
        case *layers.TCP:
            if l4.SrcPort == 53 && !pkt.Metadata().Truncated {
                vlog("reassembling %d bytes of a TCP stream: %s", len(l4.Payload), describe(pkt))
                d.assembler.AssembleWithContext(pkt.NetworkLayer().NetworkFlow(), l4, captureTime(time.Now()))
                return
            }
	}
	vlog("ignoring a queued packet: %s", describe(pkt))
}

func (d *daemon) flush() {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()

	d.assembler.FlushWithOptions(reassembly.FlushOptions{T: now.Add(-30 * time.Second), TC: now.Add(-5 * time.Minute)})
}

func (d *daemon) reload() {
	d.mu.Lock()
	defer d.mu.Unlock()
	domains, err := d.loadDomains(*domFile)
	if err != nil {
		log.Printf("reload failed, keeping %d domains: %v", len(d.domains), err)
		return
	}
	d.domains = domains
	log.Printf("loaded %d domains", len(domains))
}

func (d *daemon) reconnect() {
	c, err := nftables.New(nftables.AsLasting())
	if err != nil {
		log.Printf("reconnecting to nftables: %v", err)
		return
	}

	_ = d.nft.CloseLasting()
	d.nft = c
}

func (d *daemon) update(qname string, sets []*nftables.Set, elems [][]nftables.SetElement) {
	if *verbose || *dryRun {
		for i, set := range sets {
			for _, e := range elems[i] {
				log.Printf("%s -> %s (set %s, %s)", qname, net.IP(e.Key), set.Name, e.Timeout)
			}
		}
	}

	if *dryRun {
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
		log.Printf("updating sets for %s: %v", qname, err)
		d.reconnect()
	}
}

func addElem(list []nftables.SetElement, ip []byte, ttl uint32) []nftables.SetElement {
	if ttl > math.MaxInt32 {
		ttl = 0
	}

	timeout := min(time.Duration(ttl)*time.Second, *maxTTL)
	timeout = max((timeout + *extra).Truncate(time.Second), time.Second)

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
