package acl

import (
	"testing"
)

func TestGroupBitmask(t *testing.T) {
	// Test all subject (0..3) and object (0..3) combinations and right bitmasks (0..15)
	for sub := uint8(0); sub <= 3; sub++ {
		for obj := uint8(0); obj <= 3; obj++ {
			for r := uint8(0); r <= 15; r++ {
				g := NewGroup(sub, obj, r)
				if g.Subject() != sub {
					t.Fatalf("expected subject %d, got %d", sub, g.Subject())
				}
				if g.Object() != obj {
					t.Fatalf("expected object %d, got %d", obj, g.Object())
				}
				if g.Rights() != r {
					t.Fatalf("expected rights %d, got %d", r, g.Rights())
				}
			}
		}
	}
}

func TestGroupRights(t *testing.T) {
	// Group with Right1 (0x1) and Right3 (0x4) -> Rights = 0x5
	g := NewGroup(1, 2, Right1|Right3)
	if !g.HasRight(Right1) {
		t.Errorf("expected g to have Right1")
	}
	if g.HasRight(Right2) {
		t.Errorf("expected g NOT to have Right2")
	}
	if !g.HasRight(Right3) {
		t.Errorf("expected g to have Right3")
	}
	if g.HasRight(Right4) {
		t.Errorf("expected g NOT to have Right4")
	}
}

func TestContextGroup(t *testing.T) {
	// C == 0 means no context constraint required
	c0 := ContextGroup(0)
	if !c0.Satisfied(0) || !c0.Satisfied(0xFF) {
		t.Errorf("C=0 should always be satisfied")
	}

	// C requires flags 0x03 (bits 0 and 1)
	c := ContextGroup(0x03)
	if c.Satisfied(0x01) {
		t.Errorf("0x01 does not satisfy required 0x03")
	}
	if !c.Satisfied(0x03) {
		t.Errorf("0x03 should satisfy required 0x03")
	}
	if !c.Satisfied(0x07) {
		t.Errorf("0x07 should satisfy required 0x03")
	}
}

func TestACLPackingAndUnpacking(t *testing.T) {
	// Build ACL with 3 pairs: G1 C1 G2 C2 G3 C3
	g1 := NewGroup(1, 1, Right1)
	c1 := ContextGroup(0x01)

	g2 := NewGroup(2, 2, Right2|Right3)
	c2 := ContextGroup(0x02)

	g3 := NewGroup(3, 3, Right4)
	c3 := ContextGroup(0x04)

	acl := BuildACL(
		Pair{Group: g1, Context: c1},
		Pair{Group: g2, Context: c2},
		Pair{Group: g3, Context: c3},
	)

	// Verify pairs
	gotG1, gotC1, err := acl.GetPair(1)
	if err != nil || gotG1 != g1 || gotC1 != c1 {
		t.Fatalf("Pair 1 mismatch: got (%v, %v), expected (%v, %v)", gotG1, gotC1, g1, c1)
	}

	gotG2, gotC2, err := acl.GetPair(2)
	if err != nil || gotG2 != g2 || gotC2 != c2 {
		t.Fatalf("Pair 2 mismatch: got (%v, %v), expected (%v, %v)", gotG2, gotC2, g2, c2)
	}

	gotG3, gotC3, err := acl.GetPair(3)
	if err != nil || gotG3 != g3 || gotC3 != c3 {
		t.Fatalf("Pair 3 mismatch: got (%v, %v), expected (%v, %v)", gotG3, gotC3, g3, c3)
	}

	gotG4, gotC4, err := acl.GetPair(4)
	if err != nil || gotG4 != 0 || gotC4 != 0 {
		t.Fatalf("Pair 4 should be empty: got (%v, %v)", gotG4, gotC4)
	}
}

func TestEvaluator(t *testing.T) {
	reg := DefaultRegistry()
	eval := NewEvaluator(reg)

	// Setup ACL:
	// Group 1 (Data & Storage): Subject 1, Object 2 has READ (0x1) and WRITE (0x2). Requires context 0x01 (e.g. Work hours)
	// Group 2 (Network): Subject 2, Object 3 has PUBLISH (0x2). Requires context 0x04 (e.g. VPN)
	g1 := NewGroup(1, 2, Right1|Right2)
	c1 := ContextGroup(0x01)

	g2 := NewGroup(2, 3, Right2)
	c2 := ContextGroup(0x04)

	acl := BuildACL(
		Pair{Group: g1, Context: c1},
		Pair{Group: g2, Context: c2},
	)

	// 1. Success check Group 1 READ with context 0x01
	res := eval.Check(acl.Uint64(), 1, 1, 2, "READ", 0x01)
	if !res.Allowed {
		t.Fatalf("expected allowed, got denied: %s", res.Reason)
	}

	// 2. Failure: Context not met for Group 1 (active context is 0x02, needs 0x01)
	res = eval.Check(acl.Uint64(), 1, 1, 2, "READ", 0x02)
	if res.Allowed {
		t.Fatalf("expected denied due to context, got allowed")
	}

	// 3. Failure: Wrong subject (Subject 0 instead of 1)
	res = eval.Check(acl.Uint64(), 1, 0, 2, "READ", 0x01)
	if res.Allowed {
		t.Fatalf("expected denied due to subject mismatch, got allowed")
	}

	// 4. Failure: Wrong right (DELETE instead of READ/WRITE)
	res = eval.Check(acl.Uint64(), 1, 1, 2, "DELETE", 0x01)
	if res.Allowed {
		t.Fatalf("expected denied due to right mismatch, got allowed")
	}

	// 5. Success check Group 2 PUBLISH with context 0x05 (contains bit 0x04)
	res = eval.Check(acl.Uint64(), 2, 2, 3, "PUBLISH", 0x05)
	if !res.Allowed {
		t.Fatalf("expected allowed for group 2, got: %s", res.Reason)
	}

	// 6. Test Batch evaluation returning []bool
	// Number 1: acl (grants READ to sub 1, obj 2 with context 0x01)
	// Number 2: 0 (empty ACL -> denied)
	batchAcls := []uint64{acl.Uint64(), 0}
	boolResults := eval.CheckBatchFast(batchAcls, 1, 1, 2, "READ", 0x01)
	if len(boolResults) != 2 || !boolResults[0] || boolResults[1] {
		t.Fatalf("unexpected batch results: %v", boolResults)
	}
}
