package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

var (
	queueNum = flag.Uint("q", 0, "NFQUEUE number")
	family   = flag.String("F", "inet", "table family: ip, ip6, inet, bridge or netdev")
	table    = flag.String("t", "filter", "table containing the sets")
	def4     = flag.String("4", "", "default IPv4 set")
	def6     = flag.String("6", "", "default IPv6 set")
	domFile  = flag.String("d", "", "domain list: '[*.]domain [ipv4-set [ipv6-set]]' per line, '-' = none")
	extra    = flag.Duration("g", 48*time.Hour, "added to each answer's TTL to give the element timeout")
	maxTTL   = flag.Duration("M", 24*time.Hour, "longest TTL taken from an answer, before -g is added")
	dryRun   = flag.Bool("n", false, "log additions instead of changing sets")
	verbose  = flag.Bool("v", false, "log every address added")
)

var families = map[string]nftables.TableFamily{
	"ip":     nftables.TableFamilyIPv4,
	"ip6":    nftables.TableFamilyIPv6,
	"inet":   nftables.TableFamilyINet,
	"bridge": nftables.TableFamilyBridge,
	"netdev": nftables.TableFamilyNetdev,
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s -d FILE [options]\n"+
			"Each line of FILE is 'domain' for that name alone, or '*.domain' for it\n"+
			"and every name under it, followed by the sets to fill.\n"+
			"SIGHUP reloads the domain list.\n", os.Args[0])
		flag.VisitAll(func(f *flag.Flag) {
			if !strings.HasPrefix(f.Name, "assembly") {
				fmt.Fprintf(os.Stderr, "  -%s\t%s (default %q)\n", f.Name, f.Usage, f.DefValue)
			}
		})
	}

	flag.Parse()
	fam, ok := families[*family]
	if *domFile == "" || flag.NArg() != 0 || !ok || *queueNum > math.MaxUint16 ||
		*extra < 0 || *maxTTL < 0 {
		flag.Usage()
		os.Exit(2)
	}
	log.SetFlags(0)

	cfg := config{
		domFile: *domFile,
		def4:    *def4,
		def6:    *def6,
		extra:   *extra,
		maxTTL:  *maxTTL,
		dryRun:  *dryRun,
		verbose: *verbose,
	}
	d := newDaemon(cfg, &nftables.Table{Name: *table, Family: fam})
	var err error
	if d.nft, err = d.dial(); err != nil {
		log.Fatalf("nftables: %v", err)
	}

	defer func() { _ = d.nft.CloseLasting() }()
	if d.domains, err = d.loadDomains(cfg.domFile); err != nil {
		log.Fatal(err)
	}
	log.Printf("loaded %d domains", len(d.domains))

	nfqLog := newNfqLogger()
	nf, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      uint16(*queueNum),
		MaxPacketLen: 0xffff,
		MaxQueueLen:  4096,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagFailOpen | nfqueue.NfQaCfgFlagGSO,
		Logger:       nfqLog,
	})

	if err != nil {
		log.Fatalf("nfqueue: %v", err)
	}

	defer nf.Close()
	_ = nf.SetOption(netlink.NoENOBUFS, true)
	_ = nf.Con.SetReadBuffer(4 << 20)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	nfqLog.ctx = ctx
	d.verdict = nf.SetVerdict
	d.stopped = func() bool { return ctx.Err() != nil }

	err = nf.RegisterWithErrorFunc(ctx, d.onPacket, d.onError)

	if err != nil {
		log.Fatalf("nfqueue queue %d: %v", *queueNum, err)
	}
	netns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		netns = "unknown"
	}
	log.Printf("listening on queue %d (netlink port %d, network namespace %s)", *queueNum, nf.Con.PID(), netns)
	mon := &queueMonitor{
		num:     uint16(*queueNum),
		port:    nf.Con.PID(),
		proc:    procQueueStats,
		verbose: cfg.verbose,
		logger:  log.Default(),
	}
	mon.check()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	tick := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case err := <-d.fatal:
			log.Printf("nfqueue: %v", err)
			return
		case <-hup:
			d.reload()
		case <-tick.C:
			d.flush()
			mon.check()
		}
	}
}
