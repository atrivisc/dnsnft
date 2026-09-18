package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/florianl/go-nfqueue/v2"
	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

var (
	queueNum     = flag.Uint("q", 0, "NFQUEUE number")
	family       = flag.String("F", "inet", "table family: ip, ip6, inet, bridge or netdev")
	table        = flag.String("t", "filter", "table containing the sets")
	def4         = flag.String("4", "", "default IPv4 set")
	def6         = flag.String("6", "", "default IPv6 set")
	domFile      = flag.String("d", "", "domain list: '[*.]domain [ipv4-set [ipv6-set]]' per line, '-' = none")
	extra        = flag.Duration("g", 48*time.Hour, "added to each answer's TTL to give the element timeout")
	maxTTL       = flag.Duration("M", 24*time.Hour, "longest TTL taken from an answer, before -g is added")
	dryRun       = flag.Bool("n", false, "log additions instead of changing sets")
	verbose      = flag.Bool("v", false, "log every address added")
	sameZone     = flag.Bool("C", true, "only follow CNAMEs that stay under the matched domain")
	setSizeLimit = flag.Int("S", 100, "limits the amount of ips parsed in a response with multiple ips. Responses over this limit will be ignored")
	block        prefixList
	permit       prefixList
)

var families = map[string]nftables.TableFamily{
	"ip":     nftables.TableFamilyIPv4,
	"ip6":    nftables.TableFamilyIPv6,
	"inet":   nftables.TableFamilyINet,
	"bridge": nftables.TableFamilyBridge,
	"netdev": nftables.TableFamilyNetdev,
}

type prefixList struct {
	set bool
	ps  []netip.Prefix
}

func (p *prefixList) String() string {
	s := make([]string, len(p.ps))
	for i, q := range p.ps {
		s[i] = q.String()
	}
	return strings.Join(s, ",")
}

func (p *prefixList) Set(v string) error {
	p.set = true
	for _, f := range strings.Split(v, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		q, err := netip.ParsePrefix(f)
		if err != nil {
			return err
		}
		if q.Addr().Is4In6() {
			return fmt.Errorf("%s: write IPv4 prefixes in dotted-quad form", f)
		}
		p.ps = append(p.ps, q.Masked())
	}
	return nil
}

func mustPrefixes(s string) []netip.Prefix {
	var p prefixList
	if err := p.Set(s); err != nil {
		panic(err)
	}
	return p.ps
}

var bogons = mustPrefixes(
	"0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16," +
		"172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16," +
		"198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,240.0.0.0/4," +
		"::/128,::1/128,64:ff9b::/96,100::/64,2001:db8::/32,2002::/16," +
		"fc00::/7,fe80::/10,ff00::/8")

func main() {
	flag.Usage = func() {
		_, err := fmt.Fprintf(os.Stderr, "usage: %s -d FILE [options]\n"+
			"Each line of FILE is 'domain' for that name alone, or '*.domain' for it\n"+
			"and every name under it, followed by the sets to fill.\n"+
			"SIGHUP reloads the domain list.\n", os.Args[0])
		if err != nil {
			return
		}
		flag.VisitAll(func(f *flag.Flag) {
			if !strings.HasPrefix(f.Name, "assembly") {
				_, err := fmt.Fprintf(os.Stderr, "  -%s\t%s (default %q)\n", f.Name, f.Usage, f.DefValue)
				if err != nil {
					return
				}
			}
		})
	}

	flag.Var(&block, "X", "refuse these CIDRs in answers (repeatable; default: bogons and private space)")
	flag.Var(&permit, "A", "allow these CIDRs even if -B covers them (repeatable)")
	flag.Parse()

	fam, ok := families[*family]
	if *domFile == "" || flag.NArg() != 0 || !ok || *queueNum > math.MaxUint16 ||
		*extra < 0 || *maxTTL < 0 {
		flag.Usage()
		os.Exit(2)
	}
	log.SetFlags(0)

	if !block.set {
		block.ps = bogons
	}

	if !permit.set {
		permit.ps = mustPrefixes("")
	}

	cfg := config{
		domFile:      *domFile,
		def4:         *def4,
		def6:         *def6,
		extra:        *extra,
		maxTTL:       *maxTTL,
		dryRun:       *dryRun,
		verbose:      *verbose,
		sameZone:     *sameZone,
		setSizeLimit: *setSizeLimit,
		permit:       permit.ps,
		block:        block.ps,
	}
	d := newDaemon(cfg, &nftables.Table{Name: *table, Family: fam})
	var daemonErr error
	if d.nft, daemonErr = d.dial(); daemonErr != nil {
		log.Fatalf("nftables: %v", daemonErr)
	}

	defer func() { _ = d.nft.CloseLasting() }()
	var loadErr error
	if d.domains, loadErr = d.loadDomains(cfg.domFile); loadErr != nil {
		log.Fatal(loadErr)
	}
	log.Printf("loaded %d domains", len(d.domains))

	nfqLog := newNfqLogger()
	var queueErr error
	nf, queueErr := nfqueue.Open(&nfqueue.Config{
		NfQueue:      uint16(*queueNum),
		MaxPacketLen: 0xffff,
		MaxQueueLen:  4096,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagFailOpen | nfqueue.NfQaCfgFlagGSO,
		Logger:       nfqLog,
	})

	if queueErr != nil {
		log.Fatalf("nfqueue: %v", queueErr)
	}

	defer func(nf *nfqueue.Nfqueue) {
		err := nf.Close()
		if err != nil {
			log.Printf("nfqueue.Close: %v", err)
		}
	}(nf)

	_ = nf.SetOption(netlink.NoENOBUFS, true)
	_ = nf.Con.SetReadBuffer(4 << 20)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	nfqLog.ctx = ctx
	d.verdict = nf.SetVerdict
	d.stopped = func() bool { return ctx.Err() != nil }

	var regErr = nf.RegisterWithErrorFunc(ctx, d.onPacket, d.onError)

	if regErr != nil {
		log.Fatalf("nfqueue queue %d: %v", *queueNum, regErr)
	}
	var netns, err = os.Readlink("/proc/self/ns/net")
	if err != nil {
		netns = "unknown"
	}
	log.Printf("listening on queue %d (netlink port %d, network namespace %s)", *queueNum, nf.Con.PID(), netns)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	tick := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case err := <-d.fatal:
			log.Fatalf("nfqueue: %v", err)
		case <-hup:
			d.reload()
		case <-tick.C:
			d.flush()
		}
	}
}
