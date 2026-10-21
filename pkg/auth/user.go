package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"go-acl-bitmask/pkg/acl"
)

// EntityType indicates whether the profile is a human user or an automated process
type EntityType string

const (
	TypeUser    EntityType = "USER"
	TypeProcess EntityType = "PROCESS"
)

// Profile represents a user account or an automated system process
type Profile struct {
	ID          string     `json:"id"`           // e.g. "admin", "operator-ola", "scada-collector"
	Name        string     `json:"name"`         // Display name
	Type        EntityType `json:"type"`         // USER or PROCESS
	Role        string     `json:"role"`         // Administrator, Operator, Engineer, Background Worker
	SubjectID   uint8      `json:"subject_id"`   // 0..3 (2 bits)
	Password    string     `json:"-"`            // Plain or SHA256 hashed password
	DefaultACL  uint64     `json:"default_acl"`  // Assigned 64-bit ACL
	ACLHex      string     `json:"acl_hex"`      // Hex representation
	Description string     `json:"description"`  // Role and security scope
}

// UserStore manages users and processes
type UserStore struct {
	mu       sync.RWMutex
	profiles map[string]*Profile
}

// NewUserStore initializes pre-configured users and background processes
func NewUserStore() *UserStore {
	store := &UserStore{
		profiles: make(map[string]*Profile),
	}
	store.seedProfiles()
	return store
}

func (s *UserStore) seedProfiles() {
	// =========================================================================
	// Pre-configured ACLs for Users and Processes:
	// Bit rules reminder:
	// Subject (bits 7..6), Object (bits 5..4), Rights (bits 3..0)
	// Context requirement C: (activeContext & C) == C
	// =========================================================================

	// 1. Admin (Subject 3): Has full control across Storage (G1), Network (G2), SCADA (G3), Admin (G4)
	// Context 0 (No restriction) or 0x08 (2FA)
	g1Admin := acl.NewGroup(3, 2, acl.Right1|acl.Right2|acl.Right3|acl.Right4) // G1 all rights
	g2Admin := acl.NewGroup(3, 3, acl.Right1|acl.Right2|acl.Right3|acl.Right4) // G2 all rights
	g3Admin := acl.NewGroup(3, 1, acl.Right1|acl.Right2|acl.Right3|acl.Right4) // G3 all rights
	g4Admin := acl.NewGroup(3, 0, acl.Right1|acl.Right2|acl.Right3|acl.Right4) // G4 all rights
	adminACL := acl.BuildACL(
		acl.Pair{Group: g1Admin, Context: 0},
		acl.Pair{Group: g2Admin, Context: 0},
		acl.Pair{Group: g3Admin, Context: 0},
		acl.Pair{Group: g4Admin, Context: 0},
	)

	// 2. Operator (Subject 1):
	// G1: Sub 1, Obj 2 (Database): READ (0x1), WRITE (0x2). Requires C1 = 0x01 (Work Hours)
	// G3: Sub 1, Obj 1 (Actuators): POLL (0x1), SET_ACTUATOR (0x2). Requires C3 = 0x03 (Work Hours + Plant Location)
	g1Op := acl.NewGroup(1, 2, acl.Right1|acl.Right2)
	g3Op := acl.NewGroup(1, 1, acl.Right1|acl.Right2)
	operatorACL := acl.BuildACL(
		acl.Pair{Group: g1Op, Context: 0x01}, // Requires bit 0: Work hours
		acl.Pair{Group: 0, Context: 0},
		acl.Pair{Group: g3Op, Context: 0x03}, // Requires bit 0 (Work hours) + bit 1 (Plant location)
		acl.Pair{Group: 0, Context: 0},
	)

	// 3. Engineer (Subject 2):
	// G1: Sub 2, Obj 2 (Database): READ, WRITE, EXECUTE. Requires C1 = 0x04 (VPN/LAN)
	// G3: Sub 2, Obj 1 (Actuators): POLL, SET, CALIBRATE. Requires C3 = 0x0C (VPN/LAN + 2FA)
	g1Eng := acl.NewGroup(2, 2, acl.Right1|acl.Right2|acl.Right3)
	g3Eng := acl.NewGroup(2, 1, acl.Right1|acl.Right2|acl.Right4) // Poll, Set, Emergency
	engineerACL := acl.BuildACL(
		acl.Pair{Group: g1Eng, Context: 0x04},
		acl.Pair{Group: 0, Context: 0},
		acl.Pair{Group: g3Eng, Context: 0x0C}, // VPN + 2FA
		acl.Pair{Group: 0, Context: 0},
	)

	// 4. Guest / Auditor (Subject 0):
	// G1: READ only. No context required.
	// G3: POLL telemetry only.
	g1Guest := acl.NewGroup(0, 2, acl.Right1)
	g3Guest := acl.NewGroup(0, 0, acl.Right1)
	guestACL := acl.BuildACL(
		acl.Pair{Group: g1Guest, Context: 0},
		acl.Pair{Group: 0, Context: 0},
		acl.Pair{Group: g3Guest, Context: 0},
		acl.Pair{Group: 0, Context: 0},
	)

	// 5. Automated SCADA Poller Process (Subject 2 - Machine Worker)
	// G3: Sub 2, Obj 0 (Sensors): POLL_TELEMETRY. Context: 0x02 (Internal subnet)
	g3Poller := acl.NewGroup(2, 0, acl.Right1)
	pollerACL := acl.BuildACL(
		acl.Pair{Group: 0, Context: 0},
		acl.Pair{Group: 0, Context: 0},
		acl.Pair{Group: g3Poller, Context: 0x02},
		acl.Pair{Group: 0, Context: 0},
	)

	// 6. Backup Job Process (Subject 1 - Storage Worker)
	// G1: Sub 1, Obj 2 (Files): READ | WRITE. Requires C1 = 0x40 (Night/Maintenance Window)
	g1Backup := acl.NewGroup(1, 2, acl.Right1|acl.Right2)
	backupACL := acl.BuildACL(
		acl.Pair{Group: g1Backup, Context: 0x20}, // Bit 5: Maintenance Window
		acl.Pair{Group: 0, Context: 0},
		acl.Pair{Group: 0, Context: 0},
		acl.Pair{Group: 0, Context: 0},
	)

	// Populate profiles
	profiles := []*Profile{
		{
			ID:          "admin",
			Name:        "Administrator (System Root)",
			Type:        TypeUser,
			Role:        "Security & Infrastructure Admin",
			SubjectID:   3,
			Password:    hashPassword("admin123"),
			DefaultACL:  adminACL.Uint64(),
			ACLHex:      adminACL.Hex(),
			Description: "Full unrestricted access across all groups and security policies",
		},
		{
			ID:          "operator",
			Name:        "Ola Nordmann (Plant Operator)",
			Type:        TypeUser,
			Role:        "Shift Field Operator",
			SubjectID:   1,
			Password:    hashPassword("operator123"),
			DefaultACL:  operatorACL.Uint64(),
			ACLHex:      operatorACL.Hex(),
			Description: "Controls plant actuators during active working hours on-premise",
		},
		{
			ID:          "engineer",
			Name:        "Kari Ingeniør (Automation Engineer)",
			Type:        TypeUser,
			Role:        "SCADA & Systems Engineer",
			SubjectID:   2,
			Password:    hashPassword("engineer123"),
			DefaultACL:  engineerACL.Uint64(),
			ACLHex:      engineerACL.Hex(),
			Description: "Industrial calibration, script execution and diagnostics requiring 2FA",
		},
		{
			ID:          "guest",
			Name:        "Visitor / Auditor",
			Type:        TypeUser,
			Role:        "Auditor / Guest",
			SubjectID:   0,
			Password:    hashPassword("guest123"),
			DefaultACL:  guestACL.Uint64(),
			ACLHex:      guestACL.Hex(),
			Description: "Read-only telemetry access without modification privileges",
		},
		{
			ID:          "proc-scada-poller",
			Name:        "daemon://scada-telemetry-poller",
			Type:        TypeProcess,
			Role:        "High-Frequency Sensor Collector",
			SubjectID:   2,
			Password:    "", // Process token or secret
			DefaultACL:  pollerACL.Uint64(),
			ACLHex:      pollerACL.Hex(),
			Description: "Automated daemon polling IoT & SCADA telemetry over internal subnet",
		},
		{
			ID:          "proc-backup-worker",
			Name:        "cron://database-backup-worker",
			Type:        TypeProcess,
			Role:        "Off-Peak Data Replication Worker",
			SubjectID:   1,
			Password:    "",
			DefaultACL:  backupACL.Uint64(),
			ACLHex:      backupACL.Hex(),
			Description: "Automated cron service archiving database records during maintenance windows",
		},
	}

	for _, p := range profiles {
		s.profiles[p.ID] = p
	}
}

// Authenticate verifies username and password
func (s *UserStore) Authenticate(username, password string) (*Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.profiles[username]
	if !ok {
		return nil, fmt.Errorf("user '%s' not found", username)
	}

	if p.Password != hashPassword(password) {
		return nil, fmt.Errorf("invalid password for user '%s'", username)
	}

	return p, nil
}

// GetProfile retrieves a profile by ID
func (s *UserStore) GetProfile(id string) (*Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[id]
	return p, ok
}

// AllProfiles returns all users and processes
func (s *UserStore) AllProfiles() []*Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Profile, 0, len(s.profiles))
	for _, p := range s.profiles {
		result = append(result, p)
	}
	return result
}

func hashPassword(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}
