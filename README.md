# dnsnft

Fills nftables sets with the addresses from DNS answers, so firewall
rules can be written against wildcard domain names.

It reads DNS replies from an NFQUEUE, picks out the ones for domains you list,
and adds every A and AAAA address to a named set with a timeout. Rules that
match `ip daddr @allow4` then work for whatever the name currently resolves to,
including names behind CDNs that hand out a different address every few
minutes.

Nothing is blocked or rewritten by the daemon. Every queued packet is accepted;
the sets are the only thing it touches.

## Requirements

- Linux with `nfnetlink_queue` and the nftables `queue` statement
  (`CONFIG_NETFILTER_NETLINK_QUEUE`, `CONFIG_NFT_QUEUE`)
- CAP_NET_ADMIN, which in practice means running as root
- Go 1.27 to build

## Setting it up

### 1. Sets

The sets have to exist before the daemon starts, and they need `flags timeout`,
because every element is added with one. Key type must be `ipv4_addr` or
`ipv6_addr` to match the column it is listed in.

```
table inet filter {
    set allow4 { type ipv4_addr; flags timeout; }
    set allow6 { type ipv6_addr; flags timeout; }
}
```

### 2. A rule that queues DNS replies

```
meta l4proto { tcp, udp } th sport 53 ct direction reply queue flags bypass to 0
```

The hook decides which replies you see, and this is the easiest thing to get
wrong:

| Whose lookups | Hook to put the rule in |
| --- | --- |
| The router's own, sent to an upstream resolver | `input` |
| Answered by a resolver running on this host | `output` |
| Clients behind the router, querying an outside resolver | `forward` |

Use more than one chain if more than one applies. If the replies come from a
resolver on the same host, add `iifname != "lo"` to the input rule so they are
not processed twice.

`flags bypass` matters: without it, packets are dropped when the daemon is not
running.

### 3. The domain list

`/etc/dnsnft/domains.conf`, one entry per line:

```
# domain            [ipv4-set  [ipv6-set]]
example.com                             # this name only
*.cdn.example.com                       # the name and everything under it
*.internal.test     int4      int6      # into sets of its own
legacy.example.org  allow4    -         # IPv4 only
```

Without sets on the line the defaults from `-4` and `-6` are used. `-` leaves
that family out. Names are case insensitive and a trailing dot is fine. The
list is read at startup and on SIGHUP; if a reload fails the old list stays in
place.

### 4. Running it

```
dnsnft -d /etc/dnsnft/domains.conf -q 0 -F inet -t filter -4 allow4 -6 allow6
```

From the .deb, options other than `-d` go in `/etc/default/dnsnft`:

```
DNSNFT_OPTS="-q 0 -F inet -t filter -4 allow4 -6 allow6"
```

Then `systemctl enable --now dnsnft`, and `systemctl reload dnsnft` after
editing the domain list.

## Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `-d FILE` | required | domain list |
| `-q N` | 0 | queue number, must match the rule |
| `-F FAMILY` | inet | family of the table holding the sets |
| `-t NAME` | filter | table holding the sets |
| `-4 SET` / `-6 SET` | none | sets used for entries that name none |
| `-g DURATION` | 48h | added to the TTL to get the element timeout |
| `-M DURATION` | 24h | longest TTL taken from an answer, before `-g` |
| `-n` | off | log what would be added, change nothing |
| `-v` | off | log every packet, including the ones ignored and why |

## Timeouts

An element's timeout is `min(TTL, -M) + -g`, at least one second.

The grace period exists because a client keeps using an address long after the
TTL expires: browsers and connection pools hold onto it, and a long-lived
connection outlives the record entirely. With the defaults an address stays
allowed for about two days after it was last seen in an answer. Every new
answer refreshes the timeout, so an address in daily use never expires. `-M`
keeps a resolver handing out week-long TTLs from pinning an address for that
long.

Refreshing is done by deleting and re-adding the element in a single batch,
which is why the sets need `flags timeout` rather than fixed entries.

## What gets picked up

A reply is used when it is a response to a single IN-class question with a
NOERROR rcode, and the question name matches an entry in the list. Addresses
are taken from A and AAAA records belonging to the question name or to a CNAME
it leads to, following up to 16 names in the chain. Records for anything else
in the answer are skipped, so a reply cannot add addresses for a name you did
not ask about.

DNS over TCP works, including answers split across segments, but the daemon has
to see the connection open. Replies on a TCP connection that was already
established when it started are ignored until the connection is replaced. This
matters mostly with DNSSEC, where large answers fall back to TCP more often.

Encrypted DNS is out of reach by definition. If the resolver uses DoT or DoH
there is nothing on port 53 to read.

## Checking it works

Run with `-v` and make a lookup for a name in the list. The startup line tells
you where it is bound:

```
listening on queue 0 (netlink port 2745363674, network namespace net:[4026531833])
queue 0: 18 packets queued so far, 0 waiting for a verdict
www.example.com -> 93.184.216.34 (set allow4, 48h5m0s)
```

`nft list set inet filter allow4` should then show the address with a timeout.

If nothing happens, `cat /proc/net/netfilter/nfnetlink_queue` answers most of
it. The columns are queue number, netlink port of the bound process, packets
waiting for a verdict, copy mode, copy range, packets dropped because the queue
was full, packets that could not be delivered, and packets queued in total.

| What you see | Cause |
| --- | --- |
| No line at all | Nothing is bound in this namespace: the daemon is not running, or it runs in another namespace than the rules. The namespace it logs at startup should match `readlink /proc/self/ns/net`. |
| Total queued stays 0 | The rule never matches. Usually the wrong hook, or a queue number that differs from `-q`. |
| Total grows, nothing is logged with `-v` | Not possible in normal operation; the daemon logs a line for every packet it sees. Check that the log you are reading is the running instance. |
| `nfqueue: Could not parse message` | The library rejected a queued packet. It only understands IPv4 and IPv6 hooks, so a `queue` rule in a bridge or arp family chain will never work. Move the rule to an `ip`, `ip6` or `inet` chain. |

Warnings about packets the kernel dropped mean the daemon is not keeping up, or
its netlink receive buffer is too small.

## Building

```
go build          # binary in the working directory
go test ./...     # unit tests, no root or kernel needed
go test -race ./...
go test -run xxx -fuzz FuzzHandlePacket    # optional, feeds junk to the parser
```

Tagging `v*` builds amd64 and arm64 binaries and .deb packages through
`.github/workflows/release.yaml`. The package installs the binary,
`/etc/dnsnft/domains.conf`, `/etc/default/dnsnft` and a systemd unit.

## Layout

| File | Contents |
| --- | --- |
| `dnsnft.go` | flags, wiring, the main loop |
| `daemon.go` | queue callbacks, DNS decisions, set updates |
| `domains.go` | the domain list and name matching |
| `dns_stream.go` | DNS over TCP reassembly |
| `queuemon.go` | reads the kernel's queue statistics |
| `nfqlog.go` | surfaces errors from the nfqueue library |
| `packaging/debian` | .deb contents |

Tests live beside the code they cover. They drive the daemon with hand-built
packets and a stand-in for the nftables connection, so everything except the
wiring in `main` runs without a kernel.

## Notes

The daemon trusts the replies it is shown. It does not validate DNSSEC, so
anyone able to forge a reply that reaches the queue can put an address in a
set. Whether that matters depends on what the sets are used for.

Queued packets are always accepted, and the queue is opened with fail-open, so
DNS keeps working if the daemon dies or falls behind.