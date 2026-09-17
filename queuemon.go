package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

const procQueueStats = "/proc/self/net/netfilter/nfnetlink_queue"

type queueStats struct {
	port        uint32
	waiting     uint64
	dropped     uint64
	userDropped uint64
	queued      uint64
}

func readQueueStats(proc string, num uint16) (st queueStats, ok bool, err error) {
	data, err := os.ReadFile(proc)
	if err != nil {
		return st, false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || f[0] != strconv.Itoa(int(num)) {
			continue
		}
		var v [8]uint64
		for i := range v {
			if v[i], err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return st, false, fmt.Errorf("parsing %q: %w", line, err)
			}
		}
		return queueStats{port: uint32(v[1]), waiting: v[2], dropped: v[5], userDropped: v[6], queued: v[7]}, true, nil
	}
	return st, false, nil
}

type queueMonitor struct {
	num     uint16
	port    uint32
	proc    string
	verbose bool
	logger  *log.Logger
	problem string
	last    queueStats
}

func (m *queueMonitor) check() {
	st, ok, err := readQueueStats(m.proc, m.num)
	problem := ""
	switch {
	case err != nil:
		problem = fmt.Sprintf("cannot read kernel statistics: %v", err)
	case !ok:
		problem = "the kernel lists no process bound to it, so no packets will arrive"
	case st.port != m.port:
		problem = fmt.Sprintf("the kernel lists it as bound to netlink port %d, not ours (%d)", st.port, m.port)
	}
	if problem != m.problem && problem != "" {
		m.logger.Printf("queue %d: %s", m.num, problem)
	}
	m.problem = problem
	if problem != "" {
		return
	}

	if st.dropped > m.last.dropped || st.userDropped > m.last.userDropped {
		m.logger.Printf("queue %d: kernel dropped %d packets because the queue was full and %d it could not deliver",
			m.num, st.dropped-m.last.dropped, st.userDropped-m.last.userDropped)
	}
	if m.verbose && st.queued != m.last.queued {
		m.logger.Printf("queue %d: %d packets queued so far, %d waiting for a verdict", m.num, st.queued, st.waiting)
	}
	m.last = st
}
