package acl

import (
	"fmt"
	"strings"
	"sync"
)

// RightDefinition defines the metadata for one of the 4 rights in a group
type RightDefinition struct {
	Bit         uint8  `json:"bit"`         // 0x1, 0x2, 0x4, 0x8
	Name        string `json:"name"`        // e.g. "READ"
	Description string `json:"description"` // e.g. "Read data or telemetry"
}

// GroupDefinition describes the semantics of an ACL group
type GroupDefinition struct {
	ID          int               `json:"id"`          // 1..4
	Name        string            `json:"name"`        // e.g. "Data & Storage"
	Description string            `json:"description"` // e.g. "Controls database and file operations"
	Rights      [4]RightDefinition `json:"rights"`      // The 4 rights (bits 0..3)
}

// Registry stores the metadata and custom right definitions for all 4 groups
type Registry struct {
	mu     sync.RWMutex
	groups map[int]GroupDefinition
}

// DefaultRegistry creates the standard configuration matching the user requirements
func DefaultRegistry() *Registry {
	r := &Registry{
		groups: make(map[int]GroupDefinition),
	}

	// Group 1: Storage / Files
	r.groups[1] = GroupDefinition{
		ID:          1,
		Name:        "File & Data Storage",
		Description: "Controls permissions for reading, writing, and managing files/data",
		Rights: [4]RightDefinition{
			{Bit: Right1, Name: "READ", Description: "Read file contents or query records"},
			{Bit: Right2, Name: "WRITE", Description: "Modify file contents or insert records"},
			{Bit: Right3, Name: "EXECUTE", Description: "Run scripts or execute procedures"},
			{Bit: Right4, Name: "DELETE", Description: "Delete files or remove records"},
		},
	}

	// Group 2: Network / Messaging
	r.groups[2] = GroupDefinition{
		ID:          2,
		Name:        "Network & Messaging",
		Description: "Controls pub/sub messaging and network connectivity",
		Rights: [4]RightDefinition{
			{Bit: Right1, Name: "CONNECT", Description: "Establish connection to broker or host"},
			{Bit: Right2, Name: "PUBLISH", Description: "Publish messages to channels/topics"},
			{Bit: Right3, Name: "SUBSCRIBE", Description: "Subscribe to channels and receive topics"},
			{Bit: Right4, Name: "DISCONNECT", Description: "Terminate or evict client connections"},
		},
	}

	// Group 3: SCADA / Industrial Hardware
	r.groups[3] = GroupDefinition{
		ID:          3,
		Name:        "SCADA & Hardware",
		Description: "Controls actuators, sensors, and field controllers",
		Rights: [4]RightDefinition{
			{Bit: Right1, Name: "POLL_TELEMETRY", Description: "Read sensor values and metrics"},
			{Bit: Right2, Name: "SET_ACTUATOR", Description: "Command valves, pumps, relays"},
			{Bit: Right3, Name: "CALIBRATE", Description: "Adjust offsets and calibration parameters"},
			{Bit: Right4, Name: "EMERGENCY_STOP", Description: "Trigger immediate physical safety shutdown"},
		},
	}

	// Group 4: Administration & Security
	r.groups[4] = GroupDefinition{
		ID:          4,
		Name:        "Admin & Security",
		Description: "Controls user roles, audits, and security policies",
		Rights: [4]RightDefinition{
			{Bit: Right1, Name: "VIEW_AUDIT", Description: "Inspect audit trails and access logs"},
			{Bit: Right2, Name: "MANAGE_ROLES", Description: "Assign or revoke user permissions"},
			{Bit: Right3, Name: "CONFIG_SYSTEM", Description: "Update system settings and credentials"},
			{Bit: Right4, Name: "OVERRIDE", Description: "Administrative override of safety constraints"},
		},
	}

	return r
}

// GetGroup returns the definition for a given group (1..4)
func (r *Registry) GetGroup(id int) (GroupDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g, ok := r.groups[id]
	return g, ok
}

// AllGroups returns definitions for all registered groups
func (r *Registry) AllGroups() []GroupDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res := make([]GroupDefinition, 0, len(r.groups))
	for i := 1; i <= MaxPairs; i++ {
		if g, ok := r.groups[i]; ok {
			res = append(res, g)
		}
	}
	return res
}

// ResolveRightBit parses a right identifier (either a number 1..4, bitmask 1/2/4/8, or name "READ")
// for a specific group (1..4) into the corresponding 4-bit mask (0x1, 0x2, 0x4, 0x8)
func (r *Registry) ResolveRightBit(groupID int, rightInput any) (uint8, string, error) {
	groupDef, ok := r.GetGroup(groupID)
	if !ok {
		return 0, "", fmt.Errorf("group %d not found in registry", groupID)
	}

	switch v := rightInput.(type) {
	case string:
		upper := strings.ToUpper(strings.TrimSpace(v))
		for _, rd := range groupDef.Rights {
			if strings.EqualFold(rd.Name, upper) {
				return rd.Bit, rd.Name, nil
			}
		}
		// If string is a number like "1", "2", "4", "8"
		switch upper {
		case "1", "0X1":
			return Right1, groupDef.Rights[0].Name, nil
		case "2", "0X2":
			return Right2, groupDef.Rights[1].Name, nil
		case "3": // Index 3 (or Right 3)
			return Right3, groupDef.Rights[2].Name, nil
		case "4", "0X4":
			return Right3, groupDef.Rights[2].Name, nil
		case "8", "0X8":
			return Right4, groupDef.Rights[3].Name, nil
		default:
			return 0, "", fmt.Errorf("unknown right '%s' for group %d (%s)", v, groupID, groupDef.Name)
		}

	case float64:
		intVal := int(v)
		return r.resolveIntRight(groupID, intVal, groupDef)
	case int:
		return r.resolveIntRight(groupID, v, groupDef)
	case uint8:
		return r.resolveIntRight(groupID, int(v), groupDef)
	default:
		return 0, "", fmt.Errorf("invalid right input type %T", rightInput)
	}
}

func (r *Registry) resolveIntRight(groupID int, val int, groupDef GroupDefinition) (uint8, string, error) {
	// Case 1: Bitmask values (1, 2, 4, 8)
	switch val {
	case 1:
		return Right1, groupDef.Rights[0].Name, nil
	case 2:
		return Right2, groupDef.Rights[1].Name, nil
	case 4:
		return Right3, groupDef.Rights[2].Name, nil
	case 8:
		return Right4, groupDef.Rights[3].Name, nil
	// Case 2: 1-based index (1, 2, 3, 4)
	case 3:
		return Right3, groupDef.Rights[2].Name, nil
	default:
		return 0, "", fmt.Errorf("invalid right value %d for group %d (expected 1, 2, 4, 8 or 1..4)", val, groupID)
	}
}
