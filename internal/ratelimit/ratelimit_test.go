package ratelimit

import "testing"

func TestBurstThenThrottle(t *testing.T) {
	l := New(60, 5)
	for i := 0; i < 5; i++ {
		if !l.Allow("a") {
			t.Fatalf("request %d within burst denied", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("request beyond burst allowed")
	}
	// a different key has its own bucket
	if !l.Allow("b") {
		t.Fatal("independent key throttled")
	}
}

func TestRefill(t *testing.T) {
	l := New(6000, 1) // 100/sec — refills fast enough to test
	if !l.Allow("x") {
		t.Fatal("first denied")
	}
	if l.Allow("x") {
		t.Fatal("burst=1 allowed twice instantly")
	}
	// simulate elapsed time by rewinding the bucket clock
	l.mu.Lock()
	b := l.buckets["x"]
	b.last = b.last.Add(-100_000_000) // -100ms → +10 tokens at 100/sec
	l.mu.Unlock()
	if !l.Allow("x") {
		t.Fatal("bucket did not refill")
	}
}

func TestLowRateStillAllowsOneRequest(t *testing.T) {
	l := New(1, 0)
	if !l.Allow("x") {
		t.Fatal("rate 1/minute denied the initial request")
	}
	if l.Allow("x") {
		t.Fatal("rate 1/minute allowed more than its burst")
	}
}
