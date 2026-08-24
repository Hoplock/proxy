// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package channel

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/hoplock/proxy/internal/control"
)

// This file holds the performance claim D5 makes and PLAN §6.2 repeats: an
// un-inspected channel pays nothing for the pipeline existing.
//
// "direct" is phase 0005's pump — a bare io.Copy over the channel's reader.
// "pipeline" is the same copy with the reader taken from the pipeline first.
// They must be indistinguishable, because with no stream inspector registered
// Reader returns the very reader it was handed: no wrapper, no buffer, no
// allocation, and therefore nothing to measure per byte. "inspected" is there
// for scale — it is what a channel that someone actually attached to costs, and
// it is the only case that should differ.
//
//	go test ./internal/channel -run '^$' -bench StreamCopy -benchmem

// benchChunk is one channel read: 32 KiB, which is what io.Copy moves at a time.
var benchChunk = bytes.Repeat([]byte("hoplock"), 32*1024/7)

func BenchmarkStreamCopy(b *testing.B) {
	ctx := context.Background()
	policy := testPolicy{channels: []string{"session"}}

	newInspection := func(b *testing.B, reg *Registry) *Inspection {
		b.Helper()
		p, err := New(Options{Policy: policy, Inspectors: reg, SessionID: "bench"})
		if err != nil {
			b.Fatalf("New: %v", err)
		}
		insp, decision := p.Open(ctx, OpenEvent{ChannelType: "session", Direction: FromClient})
		if decision.Denied() {
			b.Fatal("the benchmark's own channel was denied")
		}
		return insp
	}

	b.Run("direct", func(b *testing.B) {
		src := bytes.NewReader(nil)
		b.SetBytes(int64(len(benchChunk)))
		b.ReportAllocs()
		for b.Loop() {
			src.Reset(benchChunk)
			_, _ = io.Copy(sink{}, plainReader{src})
		}
	})

	b.Run("pipeline", func(b *testing.B) {
		insp := newInspection(b, nil)
		src := bytes.NewReader(nil)
		b.SetBytes(int64(len(benchChunk)))
		b.ReportAllocs()
		for b.Loop() {
			src.Reset(benchChunk)
			_, _ = io.Copy(sink{}, insp.Reader(ctx, FromClient, false, plainReader{src}))
		}
	})

	b.Run("inspected", func(b *testing.B) {
		reg := NewRegistry()
		reg.Register("session", &stub{name: "tap", stream: func(ev *StreamEvent) io.Reader {
			return &countingReader{src: ev.Source}
		}})
		insp := newInspection(b, reg)
		src := bytes.NewReader(nil)
		b.SetBytes(int64(len(benchChunk)))
		b.ReportAllocs()
		for b.Loop() {
			src.Reset(benchChunk)
			_, _ = io.Copy(sink{}, insp.Reader(ctx, FromClient, false, plainReader{src}))
		}
	})
}

// plainReader and sink hide the WriterTo and ReaderFrom shortcuts, so io.Copy
// runs its ordinary read-write loop over a 32 KiB buffer — which is what it
// does over an ssh.Channel, and therefore what the pump really costs. Handing
// it a bytes.Reader and io.Discard instead would measure a memory move that
// never happens in the proxy.
type plainReader struct{ src io.Reader }

func (r plainReader) Read(p []byte) (int, error) { return r.src.Read(p) }

type sink struct{}

func (sink) Write(p []byte) (int, error) { return len(p), nil }

// BenchmarkOpen measures what policy costs at the moment it is decided, which
// is once per channel rather than once per byte — the whole reason the data
// path can stay a straight copy.
func BenchmarkOpen(b *testing.B) {
	ctx := context.Background()
	forward := marshalForward("db.internal", 5432)

	for _, tc := range []struct {
		name   string
		policy testPolicy
		open   OpenEvent
	}{
		{
			name:   "session",
			policy: testPolicy{channels: []string{"session"}},
			open:   OpenEvent{ChannelType: "session", Direction: FromClient},
		},
		{
			name: "direct-tcpip with a destination list",
			policy: testPolicy{
				channels: []string{control.ChannelDirectTCPIP},
				forwards: &control.ForwardPolicy{DirectTCPIP: []control.ForwardDestination{
					{Host: "*.cache.internal", PortRange: &control.PortRange{From: 6379, To: 6380}},
					{Host: "10.0.0.0/8", Port: 5432},
					{Host: "db.internal", Port: 5432},
				}},
			},
			open: OpenEvent{ChannelType: control.ChannelDirectTCPIP, Direction: FromClient, Payload: forward},
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			p, err := New(Options{Policy: tc.policy, SessionID: "bench"})
			if err != nil {
				b.Fatalf("New: %v", err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, decision := p.Open(ctx, tc.open); decision.Denied() {
					b.Fatal("the benchmark's own channel was denied")
				}
			}
		})
	}
}

// countingReader is the cheapest possible stream inspector: it looks at the
// bytes and passes them on.
type countingReader struct {
	src io.Reader
	n   int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.n += int64(n)
	return n, err
}
