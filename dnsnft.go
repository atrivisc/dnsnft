package main

import (
  "context"
  "errors"
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
  "github.com/gopacket/gopacket/reassembly"
  "github.com/mdlayher/netlink"
)

var (
  queueNum = flag.Uint("q", 0, "NFQUEUE number")
  family   = flag.String("F", "inet", "table family: ip, ip6, inet, bridge or netdev")
  table    = flag.String("t", "filter", "table containing the sets")
  def4     = flag.String("4", "", "default IPv4 set")
  def6     = flag.String("6", "", "default IPv6 set")
  domFile  = flag.String("d", "", "domain list: 'domain [ipv4-set [ipv6-set]]' per line, '-' = none")
  extra    = flag.Duration("g", 48*time.Hour, "added to each answer's TTL to give the element timeout")
  maxTTL   = flag.Duration("M", 24*time.Hour, "longest TTL taken from an answer, before -g is added")
  dryRun   = flag.Bool("n", false, "log additions instead of changing sets")
  verbose  = flag.Bool("v", false, "log every address added")
)

var families = map[string]nftables.TableFamily{
  "ip": nftables.TableFamilyIPv4, "ip6": nftables.TableFamilyIPv6,
  "inet": nftables.TableFamilyINet, "bridge": nftables.TableFamilyBridge,
  "netdev": nftables.TableFamilyNetdev,
}

func main() {
  flag.Usage = func() {
    fmt.Fprintf(os.Stderr, "usage: %s -d FILE [options]\nSIGHUP reloads the domain list.\n", os.Args[0])
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

  d := &daemon{table: &nftables.Table{Name: *table, Family: fam}}
  var err error
  if d.nft, err = nftables.New(nftables.AsLasting()); err != nil {
    log.Fatalf("nftables: %v", err)
  }

  defer func() { _ = d.nft.CloseLasting() }()
  if d.domains, err = d.loadDomains(*domFile); err != nil {
    log.Fatal(err)
  }
  log.Printf("loaded %d domains", len(d.domains))

  d.assembler = reassembly.NewAssembler(reassembly.NewStreamPool(d))
  d.assembler.MaxBufferedPagesPerConnection = 128
  d.assembler.MaxBufferedPagesTotal = 8192

  nf, err := nfqueue.Open(&nfqueue.Config{
    NfQueue:      uint16(*queueNum),
    MaxPacketLen: 0xffff,
    MaxQueueLen:  4096,
    Copymode:     nfqueue.NfQnlCopyPacket,
    Flags: nfqueue.NfQaCfgFlagFailOpen | nfqueue.NfQaCfgFlagGSO,
  })

  if err != nil {
    log.Fatalf("nfqueue: %v", err)
  }

  defer nf.Close()
  _ = nf.SetOption(netlink.NoENOBUFS, true)
  _ = nf.Con.SetReadBuffer(4 << 20)

  ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
  defer stop()
  fatal := make(chan error, 1)

  err = nf.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
    if a.PacketID == nil {
      return 0
    }
    d.mu.Lock()
    if a.Payload != nil {
      d.handlePacket(*a.Payload)
    }
    d.mu.Unlock()

    if err := nf.SetVerdict(*a.PacketID, nfqueue.NfAccept); err != nil {
      log.Printf("verdict: %v", err)
    }
    return 0
  }, func(err error) int {
    if ctx.Err() != nil || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.ENOBUFS) {
      return 0
    }
    fatal <- err
    return 1
  })

  if err != nil {
    log.Fatalf("nfqueue queue %d: %v", *queueNum, err)
  }
  log.Printf("listening on queue %d", *queueNum)

  hup := make(chan os.Signal, 1)
  signal.Notify(hup, syscall.SIGHUP)
  tick := time.NewTicker(10 * time.Second)
  for {
    select {
        case <-ctx.Done():
          return
        case err := <-fatal:
          log.Printf("nfqueue: %v", err)
          return
        case <-hup:
          d.reload()
        case <-tick.C:
          d.flush()
    }
  }
}
