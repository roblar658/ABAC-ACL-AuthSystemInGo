package acl

import (
	"fmt"
)

// CheckResult contains detailed feedback about an ACL evaluation
type CheckResult struct {
	Allowed       bool   `json:"allowed"`
	MatchedGroup  int    `json:"matched_group,omitempty"`
	RightName     string `json:"right_name,omitempty"`
	GroupName     string `json:"group_name,omitempty"`
	Reason        string `json:"reason"`
	ContextPassed bool   `json:"context_passed"`
}

// Evaluator provides high-performance ACL checking and batch processing
type Evaluator struct {
	registry *Registry
}

// NewEvaluator creates a new evaluator with the given registry
func NewEvaluator(reg *Registry) *Evaluator {
	if reg == nil {
		reg = DefaultRegistry()
	}
	return &Evaluator{registry: reg}
}

// Registry returns the underlying registry
func (e *Evaluator) Registry() *Registry {
	return e.registry
}

// Check evaluates whether the given 64-bit ACL grants the requested permission
// - targetGroup: 1..4 to check a specific group, or 0 to check all groups
// - subject: 0..3
// - object: 0..3
// - right: right identifier (e.g. "READ", 1, 2, 4, 8)
// - activeContext: active context bitmask
func (e *Evaluator) Check(aclVal uint64, targetGroup int, subject, object uint8, right any, activeContext uint8) CheckResult {
	acl := ACL(aclVal)

	startGroup := 1
	endGroup := MaxPairs
	if targetGroup >= 1 && targetGroup <= MaxPairs {
		startGroup = targetGroup
		endGroup = targetGroup
	}

	var bestFailureReason string = "No matching subject/object/rights rule found"
	contextFailed := false

	for i := startGroup; i <= endGroup; i++ {
		g, c, err := acl.GetPair(i)
		if err != nil {
			continue
		}

		// If group byte has no rights set, it cannot grant access
		if g.Rights() == 0 {
			continue
		}

		// 1. Check subject (2 bits: 0..3)
		if g.Subject() != (subject & SubjectMask) {
			continue
		}

		// 2. Check object (2 bits: 0..3)
		if g.Object() != (object & ObjectMask) {
			continue
		}

		// 3. Check rights bitmask
		rightBit, rightName, err := e.registry.ResolveRightBit(i, right)
		if err != nil {
			// Right might not exist for this group type
			continue
		}

		if !g.HasRight(rightBit) {
			continue
		}

		// 4. Corresponding Context Group (C) check:
		// "Corresponding context group must be true, to accept giving rights to group G."
		if !c.Satisfied(activeContext) {
			contextFailed = true
			bestFailureReason = fmt.Sprintf("Rule matched in Group %d (%s:%s), but Context C%d requirement (0x%02X) was not satisfied by active context (0x%02X)",
				i, e.groupName(i), rightName, i, c.Raw(), activeContext)
			continue
		}

		// Access Granted!
		return CheckResult{
			Allowed:       true,
			MatchedGroup:  i,
			RightName:     rightName,
			GroupName:     e.groupName(i),
			ContextPassed: true,
			Reason: fmt.Sprintf("Access granted by Group %d (%s) for right '%s'. Context C%d verified.",
				i, e.groupName(i), rightName, i),
		}
	}

	if contextFailed {
		return CheckResult{
			Allowed:       false,
			ContextPassed: false,
			Reason:        bestFailureReason,
		}
	}

	return CheckResult{
		Allowed:       false,
		ContextPassed: false,
		Reason:        bestFailureReason,
	}
}

// CheckBool performs a fast check returning simply true or false
func (e *Evaluator) CheckBool(aclVal uint64, targetGroup int, subject, object uint8, right any, activeContext uint8) bool {
	return e.Check(aclVal, targetGroup, subject, object, right, activeContext).Allowed
}

// CheckBatchFast processes a slice of 64-bit numbers and returns a slice of booleans ([]bool)
// directly as requested: "En kan også sende liste med nummre. En får tilbake true/false, eller liste med true/false"
func (e *Evaluator) CheckBatchFast(acls []uint64, targetGroup int, subject, object uint8, right any, activeContext uint8) []bool {
	results := make([]bool, len(acls))
	for i, a := range acls {
		results[i] = e.CheckBool(a, targetGroup, subject, object, right, activeContext)
	}
	return results
}

// CheckBatchDetailed processes a slice of 64-bit numbers and returns detailed CheckResults
func (e *Evaluator) CheckBatchDetailed(acls []uint64, targetGroup int, subject, object uint8, right any, activeContext uint8) []CheckResult {
	results := make([]CheckResult, len(acls))
	for i, a := range acls {
		results[i] = e.Check(a, targetGroup, subject, object, right, activeContext)
	}
	return results
}

func (e *Evaluator) groupName(id int) string {
	if g, ok := e.registry.GetGroup(id); ok {
		return g.Name
	}
	return fmt.Sprintf("Group %d", id)
}
