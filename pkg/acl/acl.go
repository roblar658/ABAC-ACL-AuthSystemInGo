package acl

import (
	"encoding/binary"
	"fmt"
)

// MaxPairs is 4 pairs: (G1, C1), (G2, C2), (G3, C3), (G4, C4)
// Total 4 * 8 + 4 * 8 = 64 bits
const MaxPairs = 4

// Pair bundles a Group (Gi) and its corresponding ContextGroup (Ci)
type Pair struct {
	Group   Group        `json:"group"`
	Context ContextGroup `json:"context"`
}

// ACL wraps a 64-bit integer representing the access control rules.
// Layout (big-endian byte order):
// Byte 0 (Bits 63..56): G1
// Byte 1 (Bits 55..48): C1
// Byte 2 (Bits 47..40): G2
// Byte 3 (Bits 39..32): C2
// Byte 4 (Bits 31..24): G3
// Byte 5 (Bits 23..16): C3
// Byte 6 (Bits 15..8) : G4
// Byte 7 (Bits 7..0)  : C4
type ACL uint64

// FromUint64 creates an ACL from an unsigned 64-bit integer
func FromUint64(val uint64) ACL {
	return ACL(val)
}

// Uint64 returns the underlying 64-bit integer
func (a ACL) Uint64() uint64 {
	return uint64(a)
}

// Hex returns the 16-character hexadecimal representation with 0x prefix
func (a ACL) Hex() string {
	return fmt.Sprintf("0x%016X", uint64(a))
}

// Binary returns the 64-character binary string with 0b prefix
func (a ACL) Binary() string {
	return fmt.Sprintf("0b%064b", uint64(a))
}

// Bytes returns the 8 bytes in big-endian order
func (a ACL) Bytes() [8]byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(a))
	return buf
}

// FromBytes builds an ACL from an 8-byte array
func FromBytes(b [8]byte) ACL {
	return ACL(binary.BigEndian.Uint64(b[:]))
}

// GetPair returns the Group and ContextGroup at 1-based index (1..4)
func (a ACL) GetPair(pairIndex int) (Group, ContextGroup, error) {
	if pairIndex < 1 || pairIndex > MaxPairs {
		return 0, 0, fmt.Errorf("pair index out of range (must be 1..%d, got %d)", MaxPairs, pairIndex)
	}
	shiftG := uint((MaxPairs - pairIndex) * 16 + 8)
	shiftC := uint((MaxPairs - pairIndex) * 16)

	g := Group((uint64(a) >> shiftG) & 0xFF)
	c := ContextGroup((uint64(a) >> shiftC) & 0xFF)
	return g, c, nil
}

// SetPair returns a new ACL with the specified pair updated (1-based index 1..4)
func (a ACL) SetPair(pairIndex int, g Group, c ContextGroup) (ACL, error) {
	if pairIndex < 1 || pairIndex > MaxPairs {
		return a, fmt.Errorf("pair index out of range (must be 1..%d, got %d)", MaxPairs, pairIndex)
	}
	shiftG := uint((MaxPairs - pairIndex) * 16 + 8)
	shiftC := uint((MaxPairs - pairIndex) * 16)

	mask := ^(uint64(0xFFFF) << shiftC)
	val := (uint64(a) & mask) | (uint64(g) << shiftG) | (uint64(c) << shiftC)
	return ACL(val), nil
}

// Pairs returns all 4 pairs contained in the 64-bit ACL
func (a ACL) Pairs() [MaxPairs]Pair {
	var pairs [MaxPairs]Pair
	for i := 1; i <= MaxPairs; i++ {
		g, c, _ := a.GetPair(i)
		pairs[i-1] = Pair{Group: g, Context: c}
	}
	return pairs
}

// BuildACL builds an ACL uint64 from a slice of Pairs (up to 4 pairs)
func BuildACL(pairs ...Pair) ACL {
	var val uint64
	for i, p := range pairs {
		if i >= MaxPairs {
			break
		}
		pairNum := i + 1
		shiftG := uint((MaxPairs - pairNum) * 16 + 8)
		shiftC := uint((MaxPairs - pairNum) * 16)
		val |= (uint64(p.Group) << shiftG) | (uint64(p.Context) << shiftC)
	}
	return ACL(val)
}
