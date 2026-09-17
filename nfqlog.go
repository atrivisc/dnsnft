package main

import (
	"context"
	"log"
	"sync"
	"time"
)

type nfqLogger struct {
	ctx context.Context

	mu   sync.Mutex
	last map[string]time.Time
}

func newNfqLogger() *nfqLogger {
	return &nfqLogger{last: map[string]time.Time{}}
}

func (*nfqLogger) Debugf(string, ...any) {}

func (l *nfqLogger) Errorf(format string, args ...any) {
	if l.ctx != nil && l.ctx.Err() != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if t, ok := l.last[format]; ok && now.Sub(t) < time.Minute {
		return
	}
	l.last[format] = now
	log.Printf("nfqueue: "+format, args...)
}
