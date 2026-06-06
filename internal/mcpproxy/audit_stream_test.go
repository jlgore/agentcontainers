package mcpproxy

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/audit"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcerapi"
)

// scriptedStream replays a fixed sequence of events, then returns err. After
// the script is exhausted it blocks until ctx is cancelled.
type scriptedStream struct {
	enforcerapi.Enforcer_StreamEventsClient
	ctx    context.Context
	events []*enforcerapi.EnforcementEvent
	err    error
	pos    int
}

func (s *scriptedStream) Recv() (*enforcerapi.EnforcementEvent, error) {
	if s.pos < len(s.events) {
		ev := s.events[s.pos]
		s.pos++
		return ev, nil
	}
	if s.err != nil {
		return nil, s.err
	}
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}

// scriptedStreamClient hands out one scripted stream per StreamEvents call.
type scriptedStreamClient struct {
	enforcerapi.EnforcerClient
	streams []*scriptedStream
	calls   int
}

func (c *scriptedStreamClient) StreamEvents(ctx context.Context, req *enforcerapi.StreamEventsRequest, opts ...grpc.CallOption) (enforcerapi.Enforcer_StreamEventsClient, error) {
	if c.calls >= len(c.streams) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	s := c.streams[c.calls]
	s.ctx = ctx
	c.calls++
	return s, nil
}

func enforcerEvent(comm string) *enforcerapi.EnforcementEvent {
	return &enforcerapi.EnforcementEvent{
		ContainerId: "ctr-1",
		Domain:      "process",
		Verdict:     "allow",
		Comm:        comm,
		Details:     map[string]string{"binary": "/usr/bin/" + comm},
	}
}

// A dropped stream must reconnect and record the gap: events on both sides
// of the drop land in the chain with dropped/resumed markers between them.
func TestStreamEnforcerAuditReconnectsWithGapMarkers(t *testing.T) {
	prevBase, prevMax := streamReconnectBaseDelay, streamReconnectMaxDelay
	streamReconnectBaseDelay, streamReconnectMaxDelay = time.Millisecond, 10*time.Millisecond
	defer func() { streamReconnectBaseDelay, streamReconnectMaxDelay = prevBase, prevMax }()

	sink, err := NewEnforcerAuditSink("gapsess01", t.TempDir())
	if err != nil {
		t.Fatalf("NewEnforcerAuditSink: %v", err)
	}
	defer sink.Close() //nolint:errcheck

	client := &scriptedStreamClient{streams: []*scriptedStream{
		{events: []*enforcerapi.EnforcementEvent{enforcerEvent("find")}, err: fmt.Errorf("connection reset")},
		{events: []*enforcerapi.EnforcementEvent{enforcerEvent("vol3")}}, // then blocks until cancel
	}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- StreamEnforcerAudit(ctx, client, sink) }()

	// Wait until the post-reconnect event has been written.
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, _ := audit.ReadLog(sink.Path())
		if len(entries) >= 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for reconnect; have %d entries", len(entries))
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("StreamEnforcerAudit returned %v, want context.Canceled", err)
	}

	entries, err := audit.ReadLog(sink.Path())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries (event, dropped, resumed, event), got %d", len(entries))
	}

	if entries[0].EventType != audit.EventEnforcement || entries[0].Command != "/usr/bin/find" {
		t.Errorf("entry 0 = %s %q, want enforcement /usr/bin/find", entries[0].EventType, entries[0].Command)
	}
	if entries[1].EventType != audit.EventStreamGap || entries[1].Metadata["phase"] != "dropped" {
		t.Errorf("entry 1 = %s %v, want stream_gap dropped", entries[1].EventType, entries[1].Metadata)
	}
	if entries[1].Detail != "connection reset" {
		t.Errorf("dropped detail = %q, want the stream error", entries[1].Detail)
	}
	if entries[2].EventType != audit.EventStreamGap || entries[2].Metadata["phase"] != "resumed" {
		t.Errorf("entry 2 = %s %v, want stream_gap resumed", entries[2].EventType, entries[2].Metadata)
	}
	if _, ok := entries[2].Metadata["downtimeMs"].(float64); !ok {
		t.Errorf("resumed downtimeMs = %#v, want number", entries[2].Metadata["downtimeMs"])
	}
	if entries[3].EventType != audit.EventEnforcement || entries[3].Command != "/usr/bin/vol3" {
		t.Errorf("entry 3 = %s %q, want enforcement /usr/bin/vol3", entries[3].EventType, entries[3].Command)
	}

	// Gap markers are part of the tamper-evident chain.
	if err := audit.ValidateChain(entries); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
}

// EOF from a server shutdown is a reconnectable condition, not a terminal
// one — the old behavior (return on first error) is the regression this
// guards against.
func TestStreamEnforcerAuditReconnectsOnEOF(t *testing.T) {
	prevBase, prevMax := streamReconnectBaseDelay, streamReconnectMaxDelay
	streamReconnectBaseDelay, streamReconnectMaxDelay = time.Millisecond, 10*time.Millisecond
	defer func() { streamReconnectBaseDelay, streamReconnectMaxDelay = prevBase, prevMax }()

	sink, err := NewEnforcerAuditSink("gapsess02", t.TempDir())
	if err != nil {
		t.Fatalf("NewEnforcerAuditSink: %v", err)
	}
	defer sink.Close() //nolint:errcheck

	client := &scriptedStreamClient{streams: []*scriptedStream{
		{err: io.EOF},
		{events: []*enforcerapi.EnforcementEvent{enforcerEvent("fls")}},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- StreamEnforcerAudit(ctx, client, sink) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, _ := audit.ReadLog(sink.Path())
		if len(entries) >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for reconnect after EOF")
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done

	entries, _ := audit.ReadLog(sink.Path())
	if entries[0].EventType != audit.EventStreamGap {
		t.Errorf("entry 0 = %s, want stream_gap (EOF before any event)", entries[0].EventType)
	}
	if entries[2].EventType != audit.EventEnforcement {
		t.Errorf("entry 2 = %s, want enforcement event after reconnect", entries[2].EventType)
	}
}

func TestEnforcerCommandDNSObservation(t *testing.T) {
	named := &enforcerapi.EnforcementEvent{
		Domain:  "network",
		Verdict: "allow",
		Details: map[string]string{
			"record_type": "A",
			"domain":      "intel.example.com",
			"domain_hash": "abcd1234",
			"resolved_ip": "93.184.216.34",
			"ttl":         "3600",
		},
	}
	if got := enforcerCommand(named); got != "dns A intel.example.com -> 93.184.216.34" {
		t.Errorf("named DNS command = %q", got)
	}

	// Without a reversed name the digest is still recorded — opaque but
	// correlatable within the session.
	unnamed := &enforcerapi.EnforcementEvent{
		Domain:  "network",
		Details: map[string]string{"record_type": "AAAA", "domain_hash": "abcd1234", "resolved_ip": "2001:db8::1"},
	}
	if got := enforcerCommand(unnamed); got != "dns AAAA domain#abcd1234 -> 2001:db8::1" {
		t.Errorf("unnamed DNS command = %q", got)
	}

	// Plain connect events are unaffected.
	connect := &enforcerapi.EnforcementEvent{
		Domain:  "network",
		Details: map[string]string{"dst_ip": "169.254.169.254", "dst_port": "80", "protocol": "tcp"},
	}
	if got := enforcerCommand(connect); got != "connect 169.254.169.254:80/tcp" {
		t.Errorf("connect command = %q", got)
	}
}
