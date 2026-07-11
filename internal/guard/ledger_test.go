package guard

import (
	"testing"
	"time"
)

func TestLedgerResolvePopsByToolUseID(t *testing.T) {
	l := newLedger(time.Minute, nil, nil)
	l.add(&pendingEscalation{escalationID: "g-1", toolUseID: "toolu_A", tool: "Write"})
	l.add(&pendingEscalation{escalationID: "g-2", toolUseID: "toolu_B", tool: "Bash"})

	p, ok := l.resolve("toolu_A")
	if !ok || p.escalationID != "g-1" {
		t.Fatalf("resolve(toolu_A) = %+v, %v; want g-1", p, ok)
	}
	if _, ok := l.resolve("toolu_A"); ok {
		t.Error("second resolve(toolu_A) should miss — entry already popped")
	}
	if _, ok := l.resolve("toolu_missing"); ok {
		t.Error("resolve of an unknown tool_use_id should miss")
	}
	if _, ok := l.resolve("toolu_B"); !ok {
		t.Error("toolu_B should still be resolvable")
	}
}

func TestLedgerReapExpiredOnlyTakesAged(t *testing.T) {
	l := newLedger(5*time.Minute, nil, nil)
	now := time.Unix(1_000_000, 0).UTC()
	l.now = func() time.Time { return now }

	l.add(&pendingEscalation{toolUseID: "old", askedAt: now.Add(-10 * time.Minute)})
	l.add(&pendingEscalation{toolUseID: "fresh", askedAt: now.Add(-1 * time.Minute)})

	reaped := l.reapExpired()
	if len(reaped) != 1 || reaped[0].toolUseID != "old" {
		t.Fatalf("reapExpired = %+v; want only [old]", reaped)
	}
	if _, ok := l.resolve("fresh"); !ok {
		t.Error("fresh entry must survive reaping")
	}
	if _, ok := l.resolve("old"); ok {
		t.Error("reaped entry must be gone from the ledger")
	}
}

func TestLedgerDrainAllTakesEverything(t *testing.T) {
	l := newLedger(time.Minute, nil, nil)
	l.add(&pendingEscalation{toolUseID: "a"})
	l.add(&pendingEscalation{toolUseID: "b"})
	if got := l.drainAll(); len(got) != 2 {
		t.Fatalf("drainAll returned %d entries; want 2", len(got))
	}
	if got := l.drainAll(); len(got) != 0 {
		t.Errorf("second drainAll returned %d; want 0", len(got))
	}
}
