package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"
)

func TestNfqLogger(t *testing.T) {
	t.Parallel()
	logs := &bytes.Buffer{}
	l := newNfqLogger()
	l.logger = log.New(logs, "", 0)

	l.Debugf("ignored %d", 1)
	for range 5 {
		l.Errorf("Could not parse message: %v", errors.New("invalid header"))
	}
	l.Errorf("Unknown attribute Type: 0x%x", 22)
	if n := strings.Count(logs.String(), "\n"); n != 2 {
		t.Errorf("wrote %d lines, want one per message format:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "nfqueue: Could not parse message: invalid header") {
		t.Errorf("log = %q, want the library message in it", logs.String())
	}

	ctx, cancel := context.WithCancel(context.Background())
	l.ctx = ctx
	cancel()
	logs.Reset()
	l.Errorf("Stop receiving nfqueue messages: %v", ctx.Err())
	if logs.Len() != 0 {
		t.Errorf("log = %q, want shutdown messages dropped", logs.String())
	}
}

func FuzzHandlePacket(f *testing.F) {
	msg := reply("example.com", rr{"example.com", typeA, classIN, 300, a("93.184.216.34")})
	f.Add(udp4Reply(msg))
	f.Add(udp6Reply(msg))
	f.Add(ipv4(6, tcp(50000, 1000, synAck, nil)))
	f.Add(ipv4(6, tcp(50000, 1001, pshAck, framed(msg))))
	f.Add(ipv4(17, udp(53, reply("example.com",
		rr{"example.com", typeCNAME, classIN, 300, wireName("edge.provider.net")}))))
	f.Add([]byte{0x45, 0, 0, 0})
	f.Add([]byte(nil))

	env := newTestDaemon(f)
	f.Fuzz(func(_ *testing.T, data []byte) {
		err := env.handlePacket(data)
		if err != nil {
			return
		}
	})
}
