package acl

import "fmt"

// Bitmask constants within an 8-bit group:
// Group byte layout: [Subject: 2 bits (7..6)] [Object: 2 bits (5..4)] [Rights: 4 bits (3..0)]
// Total: 8 bits (1 byte)
const (
	SubjectShift = 6
	SubjectMask  = 0x03 // 2 bits (0..3)

	ObjectShift  = 4
	ObjectMask   = 0x03 // 2 bits (0..3)

	RightsMask   = 0x0F // 4 bits (0..15 / bitmask of 4 distinct rights)
)

// Individual right bit positions (1 bit each for 4 distinct rights)
const (
	Right1 uint8 = 1 << 0 // 0x01 (Bit 0)
	Right2 uint8 = 1 << 1 // 0x02 (Bit 1)
	Right3 uint8 = 1 << 2 // 0x04 (Bit 2)
	Right4 uint8 = 1 << 3 // 0x08 (Bit 3)
)

// Group represents an 8-bit group definition
type Group uint8

// NewGroup constructs an 8-bit group from subject (0..3), object (0..3), and rights bitmask (0..15)
func NewGroup(subject, object, rights uint8) Group {
	val := ((subject & SubjectMask) << SubjectShift) |
		((object & ObjectMask) << ObjectShift) |
		(rights & RightsMask)
	return Group(val)
}

// Subject returns the 2-bit subject index (0..3)
func (g Group) Subject() uint8 {
	return uint8((g >> SubjectShift) & SubjectMask)
}

// Object returns the 2-bit object index (0..3)
func (g Group) Object() uint8 {
	return uint8((g >> ObjectShift) & ObjectMask)
}

// Rights returns the 4-bit rights bitmask (0..15)
func (g Group) Rights() uint8 {
	return uint8(g & RightsMask)
}

// HasRight checks if a specific right bitmask is granted in this group
func (g Group) HasRight(rightMask uint8) bool {
	if rightMask == 0 {
		return false
	}
	return (g.Rights() & rightMask) == rightMask
}

// HasAnyRight checks if any of the requested right bits are present
func (g Group) HasAnyRight(rightMask uint8) bool {
	return (g.Rights() & rightMask) != 0
}

// Raw returns the underlying uint8 value
func (g Group) Raw() uint8 {
	return uint8(g)
}

func (g Group) String() string {
	return fmt.Sprintf("Group(Sub:%d, Obj:%d, Rights:0x%X [%04b])",
		g.Subject(), g.Object(), g.Rights(), g.Rights())
}

// ContextGroup represents an 8-bit context constraint (C)
// For group G to grant access, corresponding C must be satisfied (true).
type ContextGroup uint8

// Raw returns the underlying uint8 value
func (c ContextGroup) Raw() uint8 {
	return uint8(c)
}

// Satisfied checks if the active context matches this context group requirement.
// Rule:
// If C == 0, no context condition is required (evaluates to true).
// If C != 0, the active context must satisfy all required bits in C: (activeContext & C) == C.
func (c ContextGroup) Satisfied(activeContext uint8) bool {
	if c == 0 {
		return true // No context restriction
	}
	return (activeContext & uint8(c)) == uint8(c)
}
