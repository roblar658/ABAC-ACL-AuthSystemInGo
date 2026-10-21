package auth

import (
	"fmt"
	"sync"
)

// Bit positions for 8-bit Context Group (Ci):
// Bit 0: Within Working Hours (Day Shift 08:00 - 16:00)
// Bit 1: On-Premises Location / Plant Floor Subnet
// Bit 2: Secure VPN Connection (Norway / HQ)
// Bit 3: Two-Factor Authentication (2FA) Verified
// Bit 4: Night Shift Hours (22:00 - 06:00)
// Bit 5: Scheduled Maintenance Window Active
// Bit 6: Weekend / Public Holiday Mode
// Bit 7: Managed Workstation / Device Compliance
const (
	CtxBitWorkHours    uint8 = 1 << 0 // 0x01
	CtxBitPlantFloor   uint8 = 1 << 1 // 0x02
	CtxBitSecureVPN    uint8 = 1 << 2 // 0x04
	CtxBit2FAVerified  uint8 = 1 << 3 // 0x08
	CtxBitNightShift   uint8 = 1 << 4 // 0x10
	CtxBitMaintenance  uint8 = 1 << 5 // 0x20
	CtxBitWeekend      uint8 = 1 << 6 // 0x40
	CtxBitManagedDevice uint8 = 1 << 7 // 0x80
)

// LocationMode defines simulated physical or network location
type LocationMode string

const (
	LocPlantFloor        LocationMode = "PLANT_FLOOR"        // Inside Industrial Plant (192.168.1.x)
	LocHQOffice          LocationMode = "HQ_OFFICE"          // Corporate HQ (Oslo Campus)
	LocRemoteVPN         LocationMode = "REMOTE_VPN"         // Remote VPN (Encrypted)
	LocUntrustedExternal LocationMode = "UNTRUSTED_EXTERNAL" // Coffee shop / Foreign IP
)

// TimeMode defines simulated time of day or operational window
type TimeMode string

const (
	TimeDayShift    TimeMode = "DAY_SHIFT"    // 08:00 - 16:00 (Standard Work Hours)
	TimeNightShift  TimeMode = "NIGHT_SHIFT"  // 22:00 - 06:00
	TimeMaintenance TimeMode = "MAINTENANCE"  // Scheduled maintenance window
	TimeWeekend     TimeMode = "WEEKEND"      // Weekend / Holiday
)

// SimulatedContext holds fake context attributes configured by user/dashboard
type SimulatedContext struct {
	Location      LocationMode `json:"location"`
	Time          TimeMode     `json:"time"`
	TwoFactorAuth bool         `json:"two_factor_auth"`
	ManagedDevice bool         `json:"managed_device"`

	// Calculated outputs
	ContextByte   uint8        `json:"context_byte"`
	ContextHex    string       `json:"context_hex"`
	ContextBinary string       `json:"context_binary"`
	ActiveFlags   []string     `json:"active_flags"`
	Description   string       `json:"description"`
}

// ContextManager maintains the active simulated context state
type ContextManager struct {
	mu     sync.RWMutex
	state  SimulatedContext
}

// NewContextManager initializes with realistic default context (Work Hours + Plant Floor + 2FA)
func NewContextManager() *ContextManager {
	cm := &ContextManager{}
	cm.SetContext(LocPlantFloor, TimeDayShift, true, true)
	return cm
}

// SetContext updates the simulated environment attributes and calculates the 8-bit context mask
func (cm *ContextManager) SetContext(loc LocationMode, tm TimeMode, twoFactor, managedDevice bool) SimulatedContext {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var mask uint8
	var flags []string

	// Location mapping
	switch loc {
	case LocPlantFloor:
		mask |= CtxBitPlantFloor
		flags = append(flags, "Plant Floor Subnet (192.168.1.x)")
	case LocHQOffice:
		mask |= CtxBitPlantFloor
		flags = append(flags, "Corporate HQ LAN (Oslo)")
	case LocRemoteVPN:
		mask |= CtxBitSecureVPN
		flags = append(flags, "Secure TLS VPN Tunnel")
	case LocUntrustedExternal:
		// No trusted location bit
		flags = append(flags, "Untrusted Public Network (External IP)")
	}

	// Time mapping
	switch tm {
	case TimeDayShift:
		mask |= CtxBitWorkHours
		flags = append(flags, "Day Shift (08:00 - 16:00)")
	case TimeNightShift:
		mask |= CtxBitNightShift
		flags = append(flags, "Night Shift (22:00 - 06:00)")
	case TimeMaintenance:
		mask |= CtxBitMaintenance
		flags = append(flags, "Maintenance Window (Off-Peak)")
	case TimeWeekend:
		mask |= CtxBitWeekend
		flags = append(flags, "Weekend / Holiday Schedule")
	}

	// Security flags
	if twoFactor {
		mask |= CtxBit2FAVerified
		flags = append(flags, "Hardware 2FA Verified")
	}
	if managedDevice {
		mask |= CtxBitManagedDevice
		flags = append(flags, "Corporate Managed Device")
	}

	cm.state = SimulatedContext{
		Location:      loc,
		Time:          tm,
		TwoFactorAuth: twoFactor,
		ManagedDevice: managedDevice,
		ContextByte:   mask,
		ContextHex:    fmt.Sprintf("0x%02X", mask),
		ContextBinary: fmt.Sprintf("0b%08b", mask),
		ActiveFlags:   flags,
		Description:   fmt.Sprintf("Spoofed: %s, %s (Mask: 0x%02X)", loc, tm, mask),
	}

	return cm.state
}

// GetCurrent returns the active simulated context
func (cm *ContextManager) GetCurrent() SimulatedContext {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.state
}
