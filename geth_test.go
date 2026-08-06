// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package log

import (
	"net"
	"testing"
	"time"
)

// The point of Stringers being generic is that it accepts a slice of a CONCRETE
// type. A []fmt.Stringer parameter compiles just as well but rejects every such
// slice at the call site, so only passing one proves the signature is right.
func TestStringersAcceptsConcreteSlice(t *testing.T) {
	durations := []time.Duration{time.Second, 2 * time.Minute}

	f := Stringers("d", durations)
	if f.Key != "d" {
		t.Fatalf("key: got %q, want %q", f.Key, "d")
	}
	got, ok := f.Value.([]time.Duration)
	if !ok {
		t.Fatalf("value was reboxed to %T; the slice must pass through unchanged", f.Value)
	}
	if len(got) != 2 || got[0] != time.Second {
		t.Fatalf("value: got %v, want %v", got, durations)
	}

	// A pointer element type is the shape the bft block scheduler passes
	// ([]*TaskWithDependents), and it is the case a non-generic signature
	// silently fails to accept.
	ips := []*net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}
	if f := Stringers("ip", ips); f.Value == nil {
		t.Fatal("a slice of pointer elements did not survive")
	}

	// []fmt.Stringer itself must still work, since T binds to fmt.Stringer —
	// otherwise widening the signature would break existing callers.
	if f := Stringers("mixed", []interface{ String() string }{time.Second}); f.Key != "mixed" {
		t.Fatalf("interface element slice rejected: %+v", f)
	}
}
