package main

import (
  "time"
  "fmt"
  "encoding/binary"
  "github.com/gopacket/gopacket"
  "github.com/gopacket/gopacket/layers"
  "github.com/gopacket/gopacket/reassembly"
)

type dnsStream struct {
  d      *daemon
  broken bool
}

func decodeDNS(dns *layers.DNS, msg []byte) (err error) {
  defer func() {
    if r := recover(); r != nil {
      err = fmt.Errorf("malformed DNS message: %v", r)
    }
  }()

  return dns.DecodeFromBytes(msg, gopacket.NilDecodeFeedback)
}

func (d *daemon) New(_, _ gopacket.Flow, _ *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
  return &dnsStream{d: d}
}

func (s *dnsStream) Accept(tcp *layers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection,
  nextSeq reassembly.Sequence, _ *bool, _ reassembly.AssemblerContext) bool {

  return !s.broken && (nextSeq != -1 || (tcp.SYN && tcp.ACK))
}

func (s *dnsStream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
  if _, _, _, skip := sg.Info(); skip != 0 {
    s.broken = true
    return
  }

  n, _ := sg.Lengths()
  data := sg.Fetch(n)
  off := 0

  for n-off >= 2 {
    size := int(binary.BigEndian.Uint16(data[off:]))
    if n-off-2 < size {
      break
    }

    s.d.handleDNS(data[off+2 : off+2+size])
    off += 2 + size
  }

  if off < n {
    sg.KeepFrom(off)
  }
}

func (s *dnsStream) ReassemblyComplete(reassembly.AssemblerContext) bool {
    return true
}

type captureTime time.Time

func (t captureTime) GetCaptureInfo() gopacket.CaptureInfo {
  return gopacket.CaptureInfo{Timestamp: time.Time(t)}
}
